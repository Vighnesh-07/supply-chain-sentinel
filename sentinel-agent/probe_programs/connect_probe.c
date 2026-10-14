/*
 * connect_probe.c -- Supply Chain Sentinel eBPF Network Tracer
 * Traces outbound TCP connections to detect C2 callbacks and exfiltration.
 */
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

struct connect_event_t {
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    u32 saddr;         /* source IPv4 */
    u32 daddr;         /* destination IPv4 */
    u16 dport;         /* destination port (host byte order) */
    u16 sport;         /* source port */
    u8  ip_proto;      /* IPPROTO_TCP = 6, IPPROTO_UDP = 17 */
};

BPF_PERF_OUTPUT(connect_events);

int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
    struct connect_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    struct inet_sock *inet = (struct inet_sock *)sk;
    event.saddr  = inet->inet_saddr;
    event.daddr  = inet->inet_daddr;
    event.dport  = ntohs(inet->inet_dport);
    event.sport  = ntohs(inet->inet_sport);
    event.ip_proto = sk->sk_protocol;

    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
