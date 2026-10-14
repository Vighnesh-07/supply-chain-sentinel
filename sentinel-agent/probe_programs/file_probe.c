/*
 * file_probe.c -- Supply Chain Sentinel eBPF File Access Tracer
 * Traces openat() calls to detect credential theft and config tampering.
 */
#include <uapi/linux/ptrace.h>
#include <uapi/linux/fcntl.h>

struct file_event_t {
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[256];
    int  flags;       /* O_RDONLY=0, O_WRONLY=1, O_RDWR=2, etc. */
    u32  uid;
};

BPF_PERF_OUTPUT(file_events);

/* Only interested in these sensitive path prefixes -- checked in userspace */
int trace_openat(struct pt_regs *ctx,
                 int dirfd,
                 const char __user *filename,
                 int flags, umode_t mode)
{
    struct file_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
    event.flags = flags;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    file_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
