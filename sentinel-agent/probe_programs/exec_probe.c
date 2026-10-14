/*
 * exec_probe.c -- Supply Chain Sentinel eBPF Exec Tracer
 * Traces execve() syscalls to detect shell spawning and package installs
 * inside containers. Uses cgroup-based container attribution.
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 timestamp;     /* ktime nanoseconds */
    char comm[TASK_COMM_LEN];
    char filename[256];
    char argv0[128];   /* First argument */
};

BPF_PERF_OUTPUT(exec_events);
BPF_HASH(active_pids, u32, u8, 1024);

int trace_execve(struct pt_regs *ctx,
                 const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp)
{
    struct exec_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    /* Only trace main thread (tid == pid) */
    if (pid != tid)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid  = pid;
    event.ppid = task->real_parent->tgid;
    event.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    /* Read first arg (argv[0]) */
    const char __user *arg0 = NULL;
    bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
    if (arg0)
        bpf_probe_read_user_str(&event.argv0, sizeof(event.argv0), arg0);

    exec_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
