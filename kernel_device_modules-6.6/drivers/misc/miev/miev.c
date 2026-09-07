// SPDX-License-Identifier: GPL-2.0-only
/*
 * MiSight event provider compatibility implementation.
 *
 * The public device-module snapshot contains only no-op mievent helpers,
 * while Dali vendor modules import the real cdev_tevent_* ABI.  The stock
 * provider uses ten preallocated 4 KiB slots and a 64 KiB FIFO.  Records in
 * the FIFO are framed as a native-endian u32 payload length followed by the
 * JSON payload; read() hides that framing from userspace.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/kfifo.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include <miev/mievent.h>

#define MIEV_NAME                    "miev"
#define MIEV_EVENT_SIZE              4096U
#define MIEV_FIFO_SIZE               (64U * 1024U)
#define MIEV_WORK_SLOTS              10U
#define MIEV_EVENT_MAGIC             0x4d494556U
#define MIEV_PAYLOAD_MAX             (MIEV_EVENT_SIZE - sizeof(struct misight_mievent))

struct miev_event_private {
	/* The public event object is the first 32 bytes of buffer. */
	char *buffer;
	struct work_struct work;
	u32 magic;
	u32 payload_len;
	u32 payload_offset;
	bool allocated;
	bool queued;
};

struct miev_device {
	dev_t devt;
	struct cdev cdev;
	struct class *class;
	struct device *device;
	struct workqueue_struct *workqueue;
	struct kfifo fifo;
	spinlock_t fifo_lock;
	spinlock_t event_lock;
	struct mutex read_lock;
	wait_queue_head_t wait_queue;
	char read_buffer[MIEV_EVENT_SIZE];
	u32 read_len;
	u32 read_offset;
	struct miev_event_private events[MIEV_WORK_SLOTS];
	bool ready;
};

static struct miev_device miev;

static struct miev_event_private *miev_event_private(
		struct misight_mievent *event)
{
	struct miev_event_private *priv;

	if (!event || !event->buf_ptr)
		return NULL;

	/* buf_ptr points to the slot's char * field, as in the stock provider. */
	priv = container_of(event->buf_ptr, struct miev_event_private, buffer);
	if (priv->magic != MIEV_EVENT_MAGIC ||
		event != (struct misight_mievent *)priv->buffer ||
		event->buf_ptr != &priv->buffer || !READ_ONCE(priv->allocated))
		return NULL;

	return priv;
}

static bool miev_fifo_has_record(void)
{
	unsigned long flags;
	bool has_record;

	spin_lock_irqsave(&miev.fifo_lock, flags);
	has_record = kfifo_len(&miev.fifo) >= sizeof(u32);
	spin_unlock_irqrestore(&miev.fifo_lock, flags);

	return has_record || READ_ONCE(miev.read_len);
}

/* Drop one complete old record so a new event can be retained. */
static bool miev_fifo_drop_one_locked(void)
{
	char discard[128];
	u32 payload_len;
	unsigned int copied;
	unsigned int left;

	if (kfifo_len(&miev.fifo) < sizeof(payload_len)) {
		kfifo_reset(&miev.fifo);
		return false;
	}

	copied = kfifo_out(&miev.fifo, &payload_len, sizeof(payload_len));
	if (copied != sizeof(payload_len) ||
		payload_len > MIEV_PAYLOAD_MAX ||
		kfifo_len(&miev.fifo) < payload_len) {
		kfifo_reset(&miev.fifo);
		return false;
	}

	left = payload_len;
	while (left) {
		unsigned int chunk = min_t(unsigned int, left, sizeof(discard));

		copied = kfifo_out(&miev.fifo, discard, chunk);
		if (copied != chunk) {
			kfifo_reset(&miev.fifo);
			return false;
		}
		left -= copied;
	}

	return true;
}

static int miev_fifo_write_record(const char *buf, unsigned int len)
{
	unsigned int record_len;
	unsigned int copied;
	unsigned long flags;

	if (!buf || !len || len > MIEV_PAYLOAD_MAX)
		return -EINVAL;

	record_len = sizeof(u32) + len;
	spin_lock_irqsave(&miev.fifo_lock, flags);
	while (kfifo_avail(&miev.fifo) < record_len) {
		if (!miev_fifo_drop_one_locked())
			break;
	}

	if (kfifo_avail(&miev.fifo) < record_len) {
		spin_unlock_irqrestore(&miev.fifo_lock, flags);
		return -ENOSPC;
	}

	copied = kfifo_in(&miev.fifo, &len, sizeof(len));
	if (copied == sizeof(len))
		copied = kfifo_in(&miev.fifo, buf, len);
	spin_unlock_irqrestore(&miev.fifo_lock, flags);

	if (copied != len)
		return -ENOSPC;

	wake_up_interruptible(&miev.wait_queue);
	return 0;
}

static void miev_event_work(struct work_struct *work)
{
	struct miev_event_private *priv =
		container_of(work, struct miev_event_private, work);
	unsigned long flags;

	/* queued keeps the slot alive after the caller destroys its event. */
	miev_fifo_write_record(priv->buffer + priv->payload_offset,
			priv->payload_len);

	spin_lock_irqsave(&miev.event_lock, flags);
	priv->queued = false;
	spin_unlock_irqrestore(&miev.event_lock, flags);
}

struct misight_mievent *cdev_tevent_alloc(unsigned int eventid)
{
	struct misight_mievent *event;
	struct miev_event_private *priv = NULL;
	unsigned long flags;
	unsigned int i;
	int len;

	if (!READ_ONCE(miev.ready))
		return NULL;

	spin_lock_irqsave(&miev.event_lock, flags);
	for (i = 0; i < MIEV_WORK_SLOTS; i++) {
		if (!miev.events[i].allocated && !miev.events[i].queued) {
			priv = &miev.events[i];
			priv->allocated = true;
			priv->magic = MIEV_EVENT_MAGIC;
			priv->payload_len = 0;
			priv->payload_offset = sizeof(struct misight_mievent);
			break;
		}
	}
	spin_unlock_irqrestore(&miev.event_lock, flags);

	if (!priv)
		return NULL;

	memset(priv->buffer, 0, MIEV_EVENT_SIZE);
	event = (struct misight_mievent *)priv->buffer;
	event->eventid = eventid;
	event->para_cnt = 0;
	event->time = ktime_get_real_seconds();
	event->buf_ptr = &priv->buffer;

	len = snprintf(priv->buffer + sizeof(*event),
			MIEV_PAYLOAD_MAX,
			"EventId %d -t %lld -paraList {", (int)eventid,
			(long long)event->time);
	if (len <= 0 || len >= MIEV_PAYLOAD_MAX) {
		spin_lock_irqsave(&miev.event_lock, flags);
		priv->magic = 0;
		priv->allocated = false;
		spin_unlock_irqrestore(&miev.event_lock, flags);
		return NULL;
	}

	event->used_size = sizeof(*event) + len;
	return event;
}
EXPORT_SYMBOL_GPL(cdev_tevent_alloc);

int cdev_tevent_add_int(struct misight_mievent *event, const char *key,
			long value)
{
	struct miev_event_private *priv = miev_event_private(event);
	struct misight_mievent *mievent;
	const char *format;
	int len;

	if (!priv || !key)
		return -1;
	mievent = (struct misight_mievent *)priv->buffer;
	if (mievent->used_size >= MIEV_EVENT_SIZE - 1)
		return -1;

	format = mievent->para_cnt ? ",\"%s\":%ld" : "\"%s\":%ld";
	len = snprintf(priv->buffer + mievent->used_size,
			MIEV_EVENT_SIZE - mievent->used_size, format, key, value);
	if (len <= 0 || len >= MIEV_EVENT_SIZE - mievent->used_size)
		return -1;

	mievent->para_cnt++;
	mievent->used_size += len;
	return 0;
}
EXPORT_SYMBOL_GPL(cdev_tevent_add_int);

int cdev_tevent_add_str(struct misight_mievent *event, const char *key,
			const char *value)
{
	struct miev_event_private *priv = miev_event_private(event);
	struct misight_mievent *mievent;
	const char *format;
	int len;

	if (!priv || !key || !value)
		return -1;
	mievent = (struct misight_mievent *)priv->buffer;
	if (mievent->used_size >= MIEV_EVENT_SIZE - 1)
		return -1;

	format = mievent->para_cnt ? ",\"%s\":\"%s\"" :
		"\"%s\":\"%s\"";
	len = snprintf(priv->buffer + mievent->used_size,
			MIEV_EVENT_SIZE - mievent->used_size, format, key, value);
	if (len <= 0 || len >= MIEV_EVENT_SIZE - mievent->used_size)
		return -1;

	mievent->para_cnt++;
	mievent->used_size += len;
	return 0;
}
EXPORT_SYMBOL_GPL(cdev_tevent_add_str);

int cdev_tevent_write(struct misight_mievent *event)
{
	struct miev_event_private *priv = miev_event_private(event);
	struct misight_mievent *mievent;
	unsigned long flags;
	unsigned int payload_len;
	int len;

	if (!priv)
		return -1;
	mievent = (struct misight_mievent *)priv->buffer;
	if (!mievent->para_cnt || mievent->used_size >= MIEV_EVENT_SIZE - 1)
		return -1;

	len = snprintf(priv->buffer + mievent->used_size,
			MIEV_EVENT_SIZE - mievent->used_size, "}");
	if (len <= 0 || len >= MIEV_EVENT_SIZE - mievent->used_size)
		return -1;

	mievent->used_size += len;
	payload_len = mievent->used_size - sizeof(*mievent);

	/* Atomic callers cannot queue work; copy the record synchronously. */
	if (in_atomic() || irqs_disabled()) {
		miev_fifo_write_record(priv->buffer + sizeof(*mievent),
				payload_len);
		return 0;
	}

	spin_lock_irqsave(&miev.event_lock, flags);
	if (!priv->allocated || priv->queued) {
		spin_unlock_irqrestore(&miev.event_lock, flags);
		return -1;
	}
	priv->payload_len = payload_len;
	priv->payload_offset = sizeof(*mievent);
	priv->queued = true;
	spin_unlock_irqrestore(&miev.event_lock, flags);

	if (!queue_work(miev.workqueue, &priv->work)) {
		spin_lock_irqsave(&miev.event_lock, flags);
		priv->queued = false;
		spin_unlock_irqrestore(&miev.event_lock, flags);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(cdev_tevent_write);

void cdev_tevent_destroy(struct misight_mievent *event)
{
	struct miev_event_private *priv = miev_event_private(event);
	unsigned long flags;

	if (!priv)
		return;

	spin_lock_irqsave(&miev.event_lock, flags);
	priv->magic = 0;
	priv->allocated = false;
	spin_unlock_irqrestore(&miev.event_lock, flags);
}
EXPORT_SYMBOL_GPL(cdev_tevent_destroy);

static int miev_load_next_record(void)
{
	unsigned int copied;
	unsigned long flags;
	u32 payload_len;

	if (miev.read_len)
		return 0;

	spin_lock_irqsave(&miev.fifo_lock, flags);
	if (kfifo_len(&miev.fifo) < sizeof(payload_len)) {
		spin_unlock_irqrestore(&miev.fifo_lock, flags);
		return -EAGAIN;
	}

	copied = kfifo_out(&miev.fifo, &payload_len, sizeof(payload_len));
	if (copied != sizeof(payload_len) || !payload_len ||
		payload_len > MIEV_PAYLOAD_MAX ||
		kfifo_len(&miev.fifo) < payload_len) {
		kfifo_reset(&miev.fifo);
		spin_unlock_irqrestore(&miev.fifo_lock, flags);
		return -EIO;
	}

	copied = kfifo_out(&miev.fifo, miev.read_buffer, payload_len);
	spin_unlock_irqrestore(&miev.fifo_lock, flags);
	if (copied != payload_len)
		return -EIO;

	miev.read_len = payload_len;
	miev.read_offset = 0;
	return 0;
}

static ssize_t miev_read(struct file *file, char __user *buf, size_t count,
		loff_t *ppos)
{
	size_t copied;
	int ret;

	if (!count)
		return 0;

	ret = mutex_lock_interruptible(&miev.read_lock);
	if (ret)
		return ret;

	while (!miev.read_len) {
		ret = miev_load_next_record();
		if (!ret)
			break;
		if (ret != -EAGAIN)
			goto out_unlock;
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out_unlock;
		}
		ret = wait_event_interruptible(miev.wait_queue,
				miev_fifo_has_record());
		if (ret)
			goto out_unlock;
	}

	copied = min_t(size_t, count, miev.read_len - miev.read_offset);
	if (copy_to_user(buf, miev.read_buffer + miev.read_offset, copied)) {
		ret = -EFAULT;
		goto out_unlock;
	}

	miev.read_offset += copied;
	if (miev.read_offset == miev.read_len) {
		miev.read_len = 0;
		miev.read_offset = 0;
	}
	ret = copied;

out_unlock:
	mutex_unlock(&miev.read_lock);
	return ret;
}

static ssize_t miev_write(struct file *file, const char __user *buf,
			size_t count, loff_t *ppos)
{
	char *kbuf;
	int ret;

	if (!count || count > MIEV_PAYLOAD_MAX)
		return -EINVAL;

	kbuf = memdup_user(buf, count);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	ret = miev_fifo_write_record(kbuf, count);
	kfree(kbuf);
	if (ret)
		return ret;

	return count;
}

static __poll_t miev_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;

	poll_wait(file, &miev.wait_queue, wait);
	if (miev_fifo_has_record())
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static long miev_ioctl(struct file *file, unsigned int cmd,
			unsigned long arg)
{
	return -ENOTTY;
}

static const struct file_operations miev_fops = {
	.owner = THIS_MODULE,
	.read = miev_read,
	.write = miev_write,
	.poll = miev_poll,
	.unlocked_ioctl = miev_ioctl,
	.llseek = no_llseek,
};

static int __init miev_init(void)
{
	unsigned int i;
	int ret;

	spin_lock_init(&miev.fifo_lock);
	spin_lock_init(&miev.event_lock);
	mutex_init(&miev.read_lock);
	init_waitqueue_head(&miev.wait_queue);

	ret = kfifo_alloc(&miev.fifo, MIEV_FIFO_SIZE, GFP_KERNEL);
	if (ret)
		return ret;

	miev.workqueue = alloc_workqueue("miev", WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!miev.workqueue) {
		kfifo_free(&miev.fifo);
		return -ENOMEM;
	}

	for (i = 0; i < MIEV_WORK_SLOTS; i++) {
		INIT_WORK(&miev.events[i].work, miev_event_work);
		miev.events[i].buffer = kzalloc(MIEV_EVENT_SIZE, GFP_KERNEL);
		if (!miev.events[i].buffer) {
			ret = -ENOMEM;
			while (i > 0)
				kfree(miev.events[--i].buffer);
			destroy_workqueue(miev.workqueue);
			miev.workqueue = NULL;
			kfifo_free(&miev.fifo);
			return ret;
		}
	}
	miev.ready = true;

	ret = alloc_chrdev_region(&miev.devt, 0, 1, MIEV_NAME);
	if (ret)
		goto err_fifo;

	cdev_init(&miev.cdev, &miev_fops);
	miev.cdev.owner = THIS_MODULE;
	ret = cdev_add(&miev.cdev, miev.devt, 1);
	if (ret)
		goto err_chrdev;

	miev.class = class_create(MIEV_NAME);
	if (IS_ERR(miev.class)) {
		ret = PTR_ERR(miev.class);
		goto err_cdev;
	}

	miev.device = device_create(miev.class, NULL, miev.devt, NULL, MIEV_NAME);
	if (IS_ERR(miev.device)) {
		ret = PTR_ERR(miev.device);
		goto err_class;
	}

	return 0;

err_class:
	class_destroy(miev.class);
err_cdev:
	cdev_del(&miev.cdev);
err_chrdev:
	unregister_chrdev_region(miev.devt, 1);
err_fifo:
	WRITE_ONCE(miev.ready, false);
	flush_workqueue(miev.workqueue);
	destroy_workqueue(miev.workqueue);
	miev.workqueue = NULL;
	for (i = 0; i < MIEV_WORK_SLOTS; i++)
		kfree(miev.events[i].buffer);
	kfifo_free(&miev.fifo);
	return ret;
}

static void __exit miev_exit(void)
{
	unsigned int i;

	WRITE_ONCE(miev.ready, false);
	device_destroy(miev.class, miev.devt);
	class_destroy(miev.class);
	cdev_del(&miev.cdev);
	unregister_chrdev_region(miev.devt, 1);
	flush_workqueue(miev.workqueue);
	destroy_workqueue(miev.workqueue);
	miev.workqueue = NULL;
	for (i = 0; i < MIEV_WORK_SLOTS; i++)
		kfree(miev.events[i].buffer);
	kfifo_free(&miev.fifo);
}

module_init(miev_init);
module_exit(miev_exit);

MODULE_DESCRIPTION("MiSight event provider");
MODULE_LICENSE("GPL");
