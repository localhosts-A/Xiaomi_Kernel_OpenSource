/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Compatibility trace ABI used by Xiaomi's closed MPBE UFS provider.
 *
 * Keep the event names, field order and print formats identical to the
 * vendor module.  The closed UFS iSE code imports only the function below,
 * but userspace tooling consumes these tracepoints when MPBE is replaced.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM mpbe

#if !defined(_TRACE_MPBE_UFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MPBE_UFS_H

#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(mpbe_ufs_send,
	TP_PROTO(__u64 delay, __u32 tid, __u16 qid, __u16 cmd, __u32 len),

	TP_ARGS(delay, tid, qid, cmd, len),

	TP_STRUCT__entry(
		__field(__u64, delay)
		__field(__u32, tid)
		__field(__u16, qid)
		__field(__u16, cmd)
		__field(__u32, len)
	),

	TP_fast_assign(
		__entry->delay = delay;
		__entry->tid = tid;
		__entry->qid = qid;
		__entry->cmd = cmd;
		__entry->len = len;
	),

	TP_printk("tid=%u qid=%u cmd=0x%02x len=%u delay=%llu",
		__entry->tid, __entry->qid, __entry->cmd,
		__entry->len, __entry->delay)
);

TRACE_EVENT(mpbe_ufs_complete,
	TP_PROTO(__u64 delay, __u32 tid, __u16 qid),

	TP_ARGS(delay, tid, qid),

	TP_STRUCT__entry(
		__field(__u64, delay)
		__field(__u32, tid)
		__field(__u16, qid)
	),

	TP_fast_assign(
		__entry->delay = delay;
		__entry->tid = tid;
		__entry->qid = qid;
	),

	TP_printk("tid=%u qid=%u delay=%llu",
		__entry->tid, __entry->qid, __entry->delay)
);

#endif /* _TRACE_MPBE_UFS_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE mpbe_ufs_trace_events

#include <trace/define_trace.h>
