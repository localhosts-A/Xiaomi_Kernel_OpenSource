// SPDX-License-Identifier: GPL-2.0-only
/*
 * Open compatibility provider for Xiaomi's closed MPBE UFS hook.
 *
 * The closed ufs-mediatek-mod-ise.ko imports exactly:
 *
 *   void mpbe_ufs_transfer_trace(struct ufs_hba *,
 *                                struct ufshcd_lrb *, u32);
 *
 * The real MPBE implementation also feeds private EARAIO state.  That
 * state is not present in the public source tree, so this provider keeps a
 * bounded, lock-protected per-HBA/per-tag accounting table and emits the
 * same public tracepoint ABI.  It deliberately does not call Blocktag: the
 * public UFS glue has already called Blocktag immediately before this hook,
 * and doing so again would double-count every request.
 */

#include <linux/blk-mq.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched/clock.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_proto.h>

#include <ufs/ufshcd.h>

#define CREATE_TRACE_POINTS
#include "mpbe_ufs_trace_events.h"
#undef CREATE_TRACE_POINTS

#define MPBE_UFS_MAX_HBAS	2
#define MPBE_UFS_MAX_QUEUES	8
#define MPBE_UFS_TAGS_PER_QUEUE	64
#define MPBE_UFS_MAX_TAGS	(MPBE_UFS_MAX_QUEUES * MPBE_UFS_TAGS_PER_QUEUE)
#define MPBE_UFS_LOGBLK_SHIFT	12

struct mpbe_ufs_tag_state {
	u64 issue_ns;
	u32 len;
	u8 opcode;
	bool active;
};

struct mpbe_ufs_state {
	struct ufs_hba *hba;
	raw_spinlock_t lock;
	struct mpbe_ufs_tag_state tags[MPBE_UFS_MAX_TAGS];
	u64 sends;
	u64 completes;
	u64 unmatched_completes;
	u64 overwritten_tags;
	u64 bytes;
	u64 total_latency_ns;
	u64 max_latency_ns;
	u64 queue_sends[MPBE_UFS_MAX_QUEUES];
	u64 queue_completes[MPBE_UFS_MAX_QUEUES];
	u64 queue_bytes[MPBE_UFS_MAX_QUEUES];
	u64 queue_latency_ns[MPBE_UFS_MAX_QUEUES];
};

static struct mpbe_ufs_state mpbe_ufs_states[MPBE_UFS_MAX_HBAS];
static struct dentry *mpbe_ufs_debugfs;
static bool mpbe_earaio = true;
static bool mpbe_log;

module_param_named(earaio, mpbe_earaio, bool, 0644);
MODULE_PARM_DESC(earaio,
		"Enable the MPBE UFS compatibility path (default: true)");
module_param_named(log_enable, mpbe_log, bool, 0644);
MODULE_PARM_DESC(log_enable, "Log accepted MPBE UFS commands");

static inline bool mpbe_ufs_is_data_cmd(const struct scsi_cmnd *cmd)
{
	u8 opcode;

	if (!cmd)
		return false;

	/* The stock predicate is (op & ~0x02) == READ(6)/READ(16). */
	opcode = cmd->cmnd[0];
	return (opcode & ~0x02U) == READ_6 ||
	       (opcode & ~0x02U) == READ_16;
}

static inline u16 mpbe_ufs_qid(struct ufs_hba *hba,
				       struct scsi_cmnd *cmd)
{
	struct request *rq;
	u32 unique_tag;
	u32 hwq;

	if (!hba || !is_mcq_enabled(hba))
		return 0;

	rq = scsi_cmd_to_rq(cmd);
	if (!rq)
		return 0;

	unique_tag = blk_mq_unique_tag(rq);
	hwq = blk_mq_unique_tag_to_hwq(unique_tag);
	if (!hba->uhq || hwq >= hba->nr_hw_queues)
		return 0;

	return (u16)hba->uhq[hwq].id;
}

static inline u32 mpbe_ufs_cdb_len(const struct scsi_cmnd *cmd)
{
	u8 opcode;
	u32 blocks;

	opcode = cmd->cmnd[0];
	switch (opcode) {
	case READ_6:
	case WRITE_6:
		blocks = cmd->cmnd[4];
		break;
	case READ_16:
	case WRITE_16:
		blocks = ((u32)cmd->cmnd[10] << 24) |
			 ((u32)cmd->cmnd[11] << 16) |
			 ((u32)cmd->cmnd[12] << 8) |
			 (u32)cmd->cmnd[13];
		break;
	default:
		return 0;
	}

	return blocks << MPBE_UFS_LOGBLK_SHIFT;
}

static struct mpbe_ufs_state *mpbe_ufs_state_for_hba(struct ufs_hba *hba)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mpbe_ufs_states); i++) {
		if (READ_ONCE(mpbe_ufs_states[i].hba) == hba)
			return &mpbe_ufs_states[i];
	}

	for (i = 0; i < ARRAY_SIZE(mpbe_ufs_states); i++) {
		if (!READ_ONCE(mpbe_ufs_states[i].hba) &&
		    cmpxchg(&mpbe_ufs_states[i].hba, NULL, hba) == NULL)
			return &mpbe_ufs_states[i];
	}

	return NULL;
}

static inline struct mpbe_ufs_tag_state *mpbe_ufs_tag(
		struct mpbe_ufs_state *state, u16 qid, u32 tid)
{
	if (qid >= MPBE_UFS_MAX_QUEUES || tid >= MPBE_UFS_TAGS_PER_QUEUE)
		return NULL;

	return &state->tags[qid * MPBE_UFS_TAGS_PER_QUEUE + tid];
}

static int mpbe_ufs_stats_show(struct seq_file *m, void *unused)
{
	unsigned int i, q;
	unsigned long flags;

	seq_printf(m, "earaio=%u log_enable=%u\n",
		   mpbe_earaio, mpbe_log);

	for (i = 0; i < ARRAY_SIZE(mpbe_ufs_states); i++) {
		struct mpbe_ufs_state *state = &mpbe_ufs_states[i];
		struct ufs_hba *hba;
		u64 sends, completes, unmatched, overwritten, bytes;
		u64 total_latency, max_latency;
		u64 queue_sends[MPBE_UFS_MAX_QUEUES];
		u64 queue_completes[MPBE_UFS_MAX_QUEUES];
		u64 queue_bytes[MPBE_UFS_MAX_QUEUES];
		u64 queue_latency[MPBE_UFS_MAX_QUEUES];

		raw_spin_lock_irqsave(&state->lock, flags);
		hba = state->hba;
		if (!hba)
			goto unlock;
		sends = state->sends;
		completes = state->completes;
		unmatched = state->unmatched_completes;
		overwritten = state->overwritten_tags;
		bytes = state->bytes;
		total_latency = state->total_latency_ns;
		max_latency = state->max_latency_ns;
		for (q = 0; q < MPBE_UFS_MAX_QUEUES; q++) {
			queue_sends[q] = state->queue_sends[q];
			queue_completes[q] = state->queue_completes[q];
			queue_bytes[q] = state->queue_bytes[q];
			queue_latency[q] = state->queue_latency_ns[q];
		}
	unlock:
		raw_spin_unlock_irqrestore(&state->lock, flags);
		if (!hba)
			continue;

		seq_printf(m,
			   "hba=%px sends=%llu completes=%llu unmatched=%llu "
			   "overwritten=%llu bytes=%llu total_latency_ns=%llu "
			   "max_latency_ns=%llu\n",
			   hba, sends, completes, unmatched, overwritten,
			   bytes, total_latency, max_latency);
		for (q = 0; q < MPBE_UFS_MAX_QUEUES; q++)
			if (queue_sends[q] || queue_completes[q])
				seq_printf(m,
					   "qid=%u sends=%llu completes=%llu bytes=%llu "
					   "latency_ns=%llu\n", q,
					   queue_sends[q], queue_completes[q],
					   queue_bytes[q], queue_latency[q]);
	}

	return 0;
}

static int mpbe_ufs_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, mpbe_ufs_stats_show, inode->i_private);
}

static const struct file_operations mpbe_ufs_stats_fops = {
	.owner = THIS_MODULE,
	.open = mpbe_ufs_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * Exact machine-level ABI imported by ufs-mediatek-mod-ise.ko.  Keep the
 * argument order and export class unchanged.  The vendor's private 6.6
 * build emits a different modversion CRC for this same 32-bit argument
 * signature, so the final vendor module metadata is pinned at packaging
 * time after modpost.
 */
void mpbe_ufs_transfer_trace(struct ufs_hba *hba,
				     struct ufshcd_lrb *lrbp, u32 is_send)
{
	struct scsi_cmnd *cmd;
	struct mpbe_ufs_state *state;
	struct mpbe_ufs_tag_state *tag;
	unsigned long flags;
	u16 qid;
	u32 tid;
	u32 len;
	u64 begin;
	u64 now;
	u64 latency = 0;
	u8 opcode;

	if (!READ_ONCE(mpbe_earaio) || !hba || !lrbp)
		return;

	cmd = READ_ONCE(lrbp->cmd);
	if (!mpbe_ufs_is_data_cmd(cmd))
		return;

	state = mpbe_ufs_state_for_hba(hba);
	if (!state)
		return;

	qid = mpbe_ufs_qid(hba, cmd);
	tid = lrbp->task_tag;
	opcode = cmd->cmnd[0];
	len = mpbe_ufs_cdb_len(cmd);
	begin = sched_clock();

	raw_spin_lock_irqsave(&state->lock, flags);
	tag = mpbe_ufs_tag(state, qid, tid);
	if (is_send) {
		if (tag) {
			if (tag->active)
				state->overwritten_tags++;
			tag->issue_ns = begin;
			tag->len = len;
			tag->opcode = opcode;
			tag->active = true;
		}
		state->sends++;
		state->bytes += len;
		if (qid < MPBE_UFS_MAX_QUEUES) {
			state->queue_sends[qid]++;
			state->queue_bytes[qid] += len;
		}
	} else {
		if (tag && tag->active) {
			latency = begin - tag->issue_ns;
			tag->active = false;
			state->total_latency_ns += latency;
			if (latency > state->max_latency_ns)
				state->max_latency_ns = latency;
			if (qid < MPBE_UFS_MAX_QUEUES)
				state->queue_latency_ns[qid] += latency;
		} else {
			state->unmatched_completes++;
		}
		state->completes++;
		if (qid < MPBE_UFS_MAX_QUEUES)
			state->queue_completes[qid]++;
	}
	raw_spin_unlock_irqrestore(&state->lock, flags);

	now = sched_clock();
	if (mpbe_log)
		pr_info_ratelimited("ufs %s tid=%u qid=%u cmd=0x%02x len=%u\n",
				    is_send ? "send" : "complete", tid, qid,
				    opcode, len);

	if (is_send)
		trace_mpbe_ufs_send(now - begin, tid, qid, opcode, len);
	else
		trace_mpbe_ufs_complete(now - begin, tid, qid);
}
EXPORT_SYMBOL_GPL(mpbe_ufs_transfer_trace);

static int __init mpbe_ufs_trace_compat_init(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mpbe_ufs_states); i++)
		raw_spin_lock_init(&mpbe_ufs_states[i].lock);

	mpbe_ufs_debugfs = debugfs_create_dir("mpbe_ufs_trace", NULL);
	if (!IS_ERR_OR_NULL(mpbe_ufs_debugfs))
		debugfs_create_file("stats", 0444, mpbe_ufs_debugfs, NULL,
				    &mpbe_ufs_stats_fops);

	pr_info("open UFS trace provider loaded; stock mpbe.ko must be absent\n");
	return 0;
}

static void __exit mpbe_ufs_trace_compat_exit(void)
{
	debugfs_remove_recursive(mpbe_ufs_debugfs);
}

module_init(mpbe_ufs_trace_compat_init);
module_exit(mpbe_ufs_trace_compat_exit);

MODULE_DESCRIPTION("Open MPBE UFS transfer trace compatibility provider");
MODULE_AUTHOR("localhosts-A/local@199771.xyz");
MODULE_LICENSE("GPL");
