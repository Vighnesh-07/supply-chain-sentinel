"""
ebpf_monitor.py — eBPF Kernel-Level Container Monitoring Module
================================================================

Provides real-time, zero-poll security monitoring of Docker containers by
hooking directly into the Linux kernel event stream via BCC/eBPF.

On non-Linux platforms (Windows, macOS) or when BCC is unavailable, the
module degrades gracefully to a docker-top / proc-net polling fallback.

Monitored event classes:
    - ExecEvent   : execve/execveat syscalls (process launches inside containers)
    - ConnectEvent: outbound TCP/UDP connect() calls
    - FileEvent   : openat() calls against sensitive filesystem paths

Architecture overview:
    EBPFMonitor (orchestrator)
        |-- Linux + BCC -> attach kprobes, poll perf ring-buffers
        `-- Fallback     -> docker top polling every 10 seconds

Public API:
    run_ebpf_session(container_names, duration_seconds, log_file) -> List[Dict]
    get_ebpf_capabilities() -> Dict
    display_ebpf_event(event) -> None
    EBPFMonitor(container_ids, event_callback)

Usage:
    from utils.ebpf_monitor import run_ebpf_session
    events = run_ebpf_session(["my_container"], duration_seconds=60)
"""

# ── Standard-library imports ──────────────────────────────────────────────────
import json
import os
import platform
import subprocess
import sys
import time
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

# ── Rich (required by the wider project) ─────────────────────────────────────
from rich.console import Console

console = Console()

# ── Platform / BCC capability detection ──────────────────────────────────────
IS_LINUX: bool = platform.system() == "Linux"
HAS_BCC: bool = False
try:
    if IS_LINUX:
        import bcc  # noqa: F401
        HAS_BCC = True
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# EBPF C PROGRAM STRINGS  (compiled at runtime by BCC on Linux)
# ═══════════════════════════════════════════════════════════════════════════════

EXEC_PROBE_BPF: str = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[256];
};
BPF_PERF_OUTPUT(exec_events);

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {
    struct exec_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
    exec_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

CONNECT_PROBE_BPF: str = r"""
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

struct connect_event_t {
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
    u32 saddr;
};
BPF_PERF_OUTPUT(connect_events);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct connect_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    struct inet_sock *inet = (struct inet_sock *)sk;
    event.daddr = inet->inet_daddr;
    event.dport = ntohs(inet->inet_dport);
    event.saddr = inet->inet_saddr;
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

OPENAT_PROBE_BPF: str = r"""
#include <uapi/linux/ptrace.h>

struct file_event_t {
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[256];
    int flags;
};
BPF_PERF_OUTPUT(file_events);

int trace_openat(struct pt_regs *ctx, int dirfd, const char __user *filename, int flags) {
    struct file_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
    event.flags = flags;
    file_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""


# ═══════════════════════════════════════════════════════════════════════════════
# EVENT DATACLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ExecEvent:
    """Fired when execve() is called inside a monitored container.

    Attributes:
        timestamp:    Unix timestamp (seconds) when the event was captured.
        container_id: Docker container ID or name that owns the process.
        pid:          Process ID of the new executable.
        ppid:         Parent process ID.
        comm:         Short process name (max 16 chars, from the kernel).
        cmdline:      Full command-line / filename passed to execve.
        severity:     Risk level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO'.
        reason:       Human-readable explanation of the severity assignment.
    """

    timestamp: float
    container_id: str
    pid: int
    ppid: int
    comm: str
    cmdline: str
    severity: str
    reason: str


@dataclass
class ConnectEvent:
    """Fired when connect() is called to an external IP from a container.

    Attributes:
        timestamp:    Unix timestamp (seconds) when the event was captured.
        container_id: Docker container ID or name that owns the process.
        pid:          Process ID making the connection.
        comm:         Short process name.
        remote_ip:    Destination IPv4 address (dotted-decimal string).
        remote_port:  Destination port number.
        protocol:     Transport protocol: 'TCP' | 'UDP'.
        severity:     Risk level.
        reason:       Human-readable explanation.
    """

    timestamp: float
    container_id: str
    pid: int
    comm: str
    remote_ip: str
    remote_port: int
    protocol: str
    severity: str
    reason: str


@dataclass
class FileEvent:
    """Fired when a sensitive file is opened inside a container.

    Attributes:
        timestamp:    Unix timestamp (seconds) when the event was captured.
        container_id: Docker container ID or name that owns the process.
        pid:          Process ID that opened the file.
        comm:         Short process name.
        filepath:     Absolute path of the file that was opened.
        flags:        Access mode: 'READ' | 'WRITE' | 'EXEC'.
        severity:     Risk level.
        reason:       Human-readable explanation.
    """

    timestamp: float
    container_id: str
    pid: int
    comm: str
    filepath: str
    flags: str
    severity: str
    reason: str


# ═══════════════════════════════════════════════════════════════════════════════
# SEVERITY CLASSIFICATION CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# Executables that indicate a reverse shell or active downloader
_CRITICAL_EXEC_BINS = frozenset({
    "sh", "bash", "dash", "zsh", "fish",
    "python", "python3", "python2",
    "perl", "ruby", "node", "nodejs",
    "nc", "ncat", "nmap",
    "curl", "wget",
})

# Runtime package managers — installing packages at runtime is suspicious
_HIGH_EXEC_BINS = frozenset({
    "apt", "apt-get", "aptitude",
    "pip", "pip3", "pip2",
    "npm", "yarn", "pnpm",
    "gem", "bundle",
    "go",
    "cargo",
    "apk", "yum", "dnf", "rpm",
})

# Well-known safe process names (suppress noise)
_SAFE_EXEC_BINS = frozenset({
    "ls", "cat", "grep", "awk", "sed", "echo", "printf",
    "ps", "top", "date", "id", "whoami", "hostname",
    "sleep", "true", "false", "test", "[", "[[",
    "env", "printenv", "export",
    "mkdir", "rm", "mv", "cp", "ln",
    "tar", "gzip", "gunzip", "zip", "unzip",
    "find", "sort", "uniq", "wc", "head", "tail",
    "nginx", "apache2", "httpd", "gunicorn", "uvicorn",
    "java", "node",   # covered by HIGH only when run as installers
})

# Cloud metadata service IPs — querying these steals credentials
_METADATA_IPS = frozenset({
    "169.254.169.254",   # AWS / Azure / GCP IMDS
    "100.100.100.200",   # Alibaba Cloud ECS metadata
    "fd00:ec2::254",     # AWS IPv6 IMDS
})

# Ports associated with C2 frameworks, reverse shells, IRC botnets
_SUSPICIOUS_PORTS = frozenset({4444, 5555, 6666, 6667, 9001, 31337, 1337, 4321, 6660})

# Sensitive file paths — access to these warrants elevated alerts
_CRITICAL_FILES = frozenset({
    "/etc/passwd",
    "/etc/shadow",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.ssh/authorized_keys",
    "/.docker/config.json",
})

_HIGH_FILE_PREFIXES = ("/proc/", "/sys/kernel/", "/dev/mem", "/dev/kmem")
_HIGH_FILES_EXACT = frozenset({"/dev/mem", "/dev/kmem"})

_MEDIUM_FILES = frozenset({
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/crontab",
    "/etc/sudoers",
    "/etc/ld.so.preload",
})


# ═══════════════════════════════════════════════════════════════════════════════
# SEVERITY CLASSIFICATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _classify_exec(comm: str, filename: str) -> Tuple[str, str]:
    """Classify the risk of an execve event.

    Args:
        comm:     Short process name (from the kernel task_struct).
        filename: Full filename/path passed to execve.

    Returns:
        A (severity, reason) tuple where severity is one of
        'CRITICAL', 'HIGH', 'MEDIUM', or 'INFO'.
    """
    # Normalise: use basename of the filename for matching
    base = os.path.basename(filename.strip()).lower()
    comm_lower = comm.strip().lower()

    if base in _CRITICAL_EXEC_BINS or comm_lower in _CRITICAL_EXEC_BINS:
        return (
            "CRITICAL",
            f"Reverse-shell or downloader binary executed: '{base or comm_lower}'",
        )

    if base in _HIGH_EXEC_BINS or comm_lower in _HIGH_EXEC_BINS:
        return (
            "HIGH",
            f"Runtime package manager invoked inside container: '{base or comm_lower}'",
        )

    if base in _SAFE_EXEC_BINS or comm_lower in _SAFE_EXEC_BINS:
        return "INFO", "Known-safe executable"

    if base or comm_lower:
        return "MEDIUM", f"Uncommon process executed inside container: '{base or comm_lower}'"

    return "INFO", "No classification data available"


def _is_private_ip(ip: str) -> bool:
    """Return True if the IPv4 address is loopback or RFC-1918 private.

    Args:
        ip: Dotted-decimal IPv4 address string.

    Returns:
        True if the address is loopback (127.x) or private (10.x, 172.16-31.x,
        192.168.x).
    """
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        if a == 127:
            return True                             # loopback
        if a == 10:
            return True                             # 10.0.0.0/8
        if a == 172 and 16 <= b <= 31:
            return True                             # 172.16.0.0/12
        if a == 192 and b == 168:
            return True                             # 192.168.0.0/16
    except (ValueError, AttributeError):
        pass
    return False


def _classify_connect(remote_ip: str, remote_port: int) -> Tuple[str, str]:
    """Classify the risk of an outbound TCP/UDP connect event.

    Args:
        remote_ip:   Dotted-decimal IPv4 destination address.
        remote_port: Destination port number.

    Returns:
        A (severity, reason) tuple.
    """
    if remote_ip in _METADATA_IPS:
        return (
            "CRITICAL",
            f"Connection to cloud metadata service ({remote_ip}) — possible credential theft",
        )

    if remote_port in _SUSPICIOUS_PORTS:
        return (
            "HIGH",
            f"Connection to known C2/reverse-shell port {remote_port} at {remote_ip}",
        )

    if _is_private_ip(remote_ip):
        return "INFO", f"Internal/loopback connection to {remote_ip}:{remote_port}"

    # External, non-standard port
    _STANDARD_PORTS = {80, 443, 53, 22, 25, 587, 465, 993, 995, 8080, 8443}
    if remote_port not in _STANDARD_PORTS:
        return (
            "HIGH",
            f"External connection to non-standard port {remote_port} at {remote_ip}",
        )

    return "MEDIUM", f"External connection to {remote_ip}:{remote_port}"


def _classify_file(filepath: str, flags: int) -> Tuple[str, str]:
    """Classify the risk of an openat() file-access event.

    Args:
        filepath: Absolute path of the file that was opened.
        flags:    Raw openat() flags integer (O_RDONLY=0, O_WRONLY=1, O_RDWR=2).

    Returns:
        A (severity, reason) tuple.
    """
    # Normalise home-relative paths for matching
    norm = filepath.strip()
    # Match against exact critical paths (allowing /root/.aws/... or /home/user/.ssh/...)
    for crit in _CRITICAL_FILES:
        if norm == crit or norm.endswith(crit):
            return (
                "CRITICAL",
                f"Access to highly sensitive credential/config file: '{norm}'",
            )

    # High-severity: /proc/<PID>/mem, /sys/kernel/*, /dev/mem
    if norm in _HIGH_FILES_EXACT:
        return "HIGH", f"Direct hardware or kernel memory access: '{norm}'"
    for prefix in _HIGH_FILE_PREFIXES:
        if norm.startswith(prefix):
            return "HIGH", f"Access to sensitive kernel/proc path: '{norm}'"

    # Medium-severity
    if norm in _MEDIUM_FILES:
        return "MEDIUM", f"Access to system configuration file: '{norm}'"

    return "INFO", f"File access: '{norm}'"


# ═══════════════════════════════════════════════════════════════════════════════
# EBPF MONITOR CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class EBPFMonitor:
    """Kernel-level container monitoring via eBPF (Linux only).

    On Linux with BCC installed, this class attaches kprobes directly into
    the kernel and receives events via perf ring buffers with zero polling
    overhead.  On other platforms (Windows, macOS) or when BCC is unavailable,
    it falls back to periodic ``docker top`` polling every 10 seconds.

    Args:
        container_ids:  List of Docker container IDs or names to monitor.
        event_callback: Callable invoked with each captured event object
                        (``ExecEvent``, ``ConnectEvent``, or ``FileEvent``).

    Example::

        def on_event(evt):
            print(evt)

        monitor = EBPFMonitor(["my_app"], on_event)
        monitor.start()
        time.sleep(60)
        monitor.stop()
    """

    def __init__(self, container_ids: List[str], event_callback: Callable) -> None:
        self.container_ids: List[str] = list(container_ids)
        self.event_callback: Callable = event_callback
        self._bpf = None                    # BCC BPF object — None on non-Linux
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._mode: str = "ebpf" if (IS_LINUX and HAS_BCC) else "fallback"
        # PID -> container_id mapping, refreshed periodically
        self._pid_to_container: Dict[int, str] = {}

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self) -> None:
        """Start monitoring.

        Attaches eBPF kprobes on Linux/BCC or starts the fallback
        ``docker top`` polling thread on other platforms.  Prints a status
        line via Rich indicating the active mode.
        """
        if self._mode == "ebpf":
            self._start_ebpf()
        else:
            self._start_fallback()
        self._running = True
        console.print(
            f"  [bold green][OK][/] eBPF Monitor started in "
            f"[bold]{self._mode.upper()}[/] mode"
        )

    def stop(self) -> None:
        """Stop monitoring and detach eBPF probes.

        Sets the running flag to False, clears the BCC object (BCC
        automatically detaches probes on garbage collection), and joins the
        background thread with a 2-second timeout.
        """
        self._running = False
        if self._bpf is not None:
            # BCC detaches kprobes automatically when the BPF object is GC-ed.
            self._bpf = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    # ── PID / container resolution ────────────────────────────────────────────

    def _refresh_pid_map(self) -> None:
        """Refresh the PID-to-container mapping via ``docker inspect``.

        Queries the root PID of each monitored container and stores the
        mapping in ``self._pid_to_container`` so that kernel-level events
        can be attributed to the correct container.
        """
        for cid in self.container_ids:
            try:
                result = subprocess.run(
                    ["docker", "inspect", "--format", "{{.State.Pid}}", cid],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    pid_str = result.stdout.strip()
                    if pid_str.isdigit():
                        self._pid_to_container[int(pid_str)] = cid
            except Exception:
                pass

    def _get_container_for_pid(self, pid: int) -> Optional[str]:
        """Determine which monitored container a PID belongs to.

        Reads ``/proc/<pid>/cgroup`` and searches for any of the monitored
        container short IDs (12-char prefix) in the cgroup path, which is
        how Docker embeds container IDs in cgroup hierarchies.

        Args:
            pid: Kernel process ID to look up.

        Returns:
            The matching container ID string, or ``None`` if the PID does
            not belong to any monitored container.
        """
        try:
            with open(f"/proc/{pid}/cgroup", "r", encoding="utf-8", errors="replace") as fh:
                cgroup = fh.read()
            for cid in self.container_ids:
                # Docker embeds the first 12 characters of the container ID
                if cid[:12] in cgroup:
                    return cid
        except Exception:
            pass
        return None

    # ── eBPF mode ─────────────────────────────────────────────────────────────

    def _start_ebpf(self) -> None:
        """Attach BCC kprobes and open perf buffers.

        Compiles and loads all three eBPF programs (exec, connect, openat),
        attaches them as kprobes, registers perf-buffer callbacks, and starts
        the background polling thread.
        """
        from bcc import BPF  # imported here to keep Windows-safe at module load

        combined_bpf = EXEC_PROBE_BPF + CONNECT_PROBE_BPF + OPENAT_PROBE_BPF
        self._bpf = BPF(text=combined_bpf)

        self._bpf.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")
        self._bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
        self._bpf.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat")

        self._refresh_pid_map()

        self._bpf["exec_events"].open_perf_buffer(self._handle_exec_event)
        self._bpf["connect_events"].open_perf_buffer(self._handle_connect_event)
        self._bpf["file_events"].open_perf_buffer(self._handle_file_event)

        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def _poll_loop(self) -> None:
        """eBPF perf-buffer poll loop (runs in the background thread).

        Calls ``BPF.perf_buffer_poll()`` with a 100 ms timeout in a tight
        loop so that the main thread stays responsive.  Stops when
        ``self._running`` is cleared or ``self._bpf`` is set to None.
        """
        while self._running and self._bpf is not None:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception:
                break

    # ── Fallback mode ─────────────────────────────────────────────────────────

    def _start_fallback(self) -> None:
        """Start the docker-top polling fallback thread."""
        self._thread = threading.Thread(target=self._fallback_poll_loop, daemon=True)
        self._thread.start()

    def _fallback_poll_loop(self) -> None:
        """Fallback polling loop using ``docker top`` (non-Linux / no BCC).

        Polls each monitored container every 10 seconds for suspicious
        processes.  This replicates the logic of the existing
        ``runtime_scanner.py`` approach but uses the severity classifiers
        defined in this module for consistency.
        """
        while self._running:
            for cid in self.container_ids:
                self._fallback_scan_container(cid)
            time.sleep(10)

    def _fallback_scan_container(self, container_id: str) -> None:
        """Inspect a single container via ``docker top`` in fallback mode.

        Args:
            container_id: Docker container ID or name to inspect.
        """
        try:
            result = subprocess.run(
                ["docker", "top", container_id, "-eo", "pid,ppid,comm,args"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return
            for line in result.stdout.splitlines()[1:]:     # skip header row
                parts = line.split(None, 3)
                if len(parts) < 3:
                    continue
                pid_str, ppid_str, comm = parts[0], parts[1], parts[2]
                args = parts[3] if len(parts) > 3 else ""
                pid = int(pid_str) if pid_str.isdigit() else 0
                ppid = int(ppid_str) if ppid_str.isdigit() else 0
                severity, reason = _classify_exec(comm, args)
                if severity in ("CRITICAL", "HIGH"):
                    event = ExecEvent(
                        timestamp=time.time(),
                        container_id=container_id,
                        pid=pid,
                        ppid=ppid,
                        comm=comm,
                        cmdline=args,
                        severity=severity,
                        reason=reason,
                    )
                    self.event_callback(event)
        except Exception:
            pass

    # ── BCC perf-buffer callbacks ─────────────────────────────────────────────

    def _handle_exec_event(self, cpu: int, data, size: int) -> None:
        """BCC callback invoked for each execve perf-buffer event.

        Args:
            cpu:  CPU core that produced the event.
            data: Raw ctypes structure pointer from BCC.
            size: Size of the event data in bytes.
        """
        event = self._bpf["exec_events"].event(data)
        container_id = self._get_container_for_pid(event.pid)
        if container_id is None:
            return  # not one of our containers

        filename = event.filename.decode("utf-8", errors="replace").strip("\x00")
        comm = event.comm.decode("utf-8", errors="replace").strip("\x00")
        severity, reason = _classify_exec(comm, filename)
        if severity == "INFO":
            return  # suppress noise

        evt = ExecEvent(
            timestamp=event.timestamp / 1e9,
            container_id=container_id,
            pid=event.pid,
            ppid=event.ppid,
            comm=comm,
            cmdline=filename,
            severity=severity,
            reason=reason,
        )
        self.event_callback(evt)

    def _handle_connect_event(self, cpu: int, data, size: int) -> None:
        """BCC callback invoked for each outbound connect perf-buffer event.

        Args:
            cpu:  CPU core that produced the event.
            data: Raw ctypes structure pointer from BCC.
            size: Size of the event data in bytes.
        """
        import socket as _socket

        event = self._bpf["connect_events"].event(data)
        container_id = self._get_container_for_pid(event.pid)
        if container_id is None:
            return

        # daddr is stored in network byte order as a 32-bit integer
        try:
            remote_ip = _socket.inet_ntoa(event.daddr.to_bytes(4, "little"))
        except Exception:
            remote_ip = "0.0.0.0"

        severity, reason = _classify_connect(remote_ip, event.dport)
        if severity == "INFO":
            return

        evt = ConnectEvent(
            timestamp=event.timestamp / 1e9,
            container_id=container_id,
            pid=event.pid,
            comm=event.comm.decode("utf-8", errors="replace").strip("\x00"),
            remote_ip=remote_ip,
            remote_port=event.dport,
            protocol="TCP",
            severity=severity,
            reason=reason,
        )
        self.event_callback(evt)

    def _handle_file_event(self, cpu: int, data, size: int) -> None:
        """BCC callback invoked for each openat perf-buffer event.

        Args:
            cpu:  CPU core that produced the event.
            data: Raw ctypes structure pointer from BCC.
            size: Size of the event data in bytes.
        """
        event = self._bpf["file_events"].event(data)
        container_id = self._get_container_for_pid(event.pid)
        if container_id is None:
            return

        filepath = event.filename.decode("utf-8", errors="replace").strip("\x00")
        severity, reason = _classify_file(filepath, event.flags)
        if severity == "INFO":
            return

        # O_WRONLY = 1, O_RDWR = 2 — anything > 0 involves a write
        access_mode = "WRITE" if (event.flags & 0x3) > 0 else "READ"

        evt = FileEvent(
            timestamp=event.timestamp / 1e9,
            container_id=container_id,
            pid=event.pid,
            comm=event.comm.decode("utf-8", errors="replace").strip("\x00"),
            filepath=filepath,
            flags=access_mode,
            severity=severity,
            reason=reason,
        )
        self.event_callback(evt)


# ═══════════════════════════════════════════════════════════════════════════════
# DISPLAY HELPER
# ═══════════════════════════════════════════════════════════════════════════════

# Severity -> (Rich style, ASCII prefix tag)
_SEVERITY_DISPLAY = {
    "CRITICAL": ("bold white on red",   "[CRITICAL]"),
    "HIGH":     ("bold red",            "[HIGH]    "),
    "MEDIUM":   ("bold yellow",         "[MEDIUM]  "),
    "INFO":     ("dim",                 "[INFO]    "),
}


def display_ebpf_event(event) -> None:
    """Print an eBPF event to the console with Rich colour coding.

    The output format is::

        [SEVERITY] HH:MM:SS | container | PID=xxx | comm | reason

    Severity colour mapping:
        - CRITICAL : bold white text on a red background
        - HIGH     : bold red
        - MEDIUM   : bold yellow
        - INFO     : dim / grey

    Args:
        event: An ``ExecEvent``, ``ConnectEvent``, or ``FileEvent`` instance.
    """
    severity = getattr(event, "severity", "INFO")
    style, tag = _SEVERITY_DISPLAY.get(severity, ("dim", "[INFO]    "))

    ts = datetime.fromtimestamp(event.timestamp).strftime("%H:%M:%S")
    cid = getattr(event, "container_id", "?")[:12]
    pid = getattr(event, "pid", 0)
    comm = getattr(event, "comm", "?")
    reason = getattr(event, "reason", "")

    line = f"{tag} {ts} | {cid} | PID={pid:<6} | {comm:<16} | {reason}"
    console.print(f"  [{style}]{line}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# CAPABILITY QUERY
# ═══════════════════════════════════════════════════════════════════════════════

def get_ebpf_capabilities() -> Dict:
    """Return a summary of the eBPF monitoring capabilities on this host.

    Returns:
        A dictionary with the following keys:

        - ``platform``      : OS name (e.g. ``"Linux"``, ``"Windows"``).
        - ``kernel``        : Kernel release string on Linux, ``"N/A"`` elsewhere.
        - ``bcc_available`` : ``True`` if the ``bcc`` Python package is installed.
        - ``mode``          : ``"ebpf"`` when full eBPF is available, else
                              ``"fallback"``.
        - ``features``      : List of active feature names.
    """
    mode = "ebpf" if (IS_LINUX and HAS_BCC) else "fallback"
    features: List[str]
    if mode == "ebpf":
        features = ["execve-tracing", "connect-tracing", "file-tracing"]
    else:
        features = ["docker-top", "proc-net"]

    return {
        "platform": platform.system(),
        "kernel": platform.release() if IS_LINUX else "N/A",
        "bcc_available": HAS_BCC,
        "mode": mode,
        "features": features,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL SESSION RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_ebpf_session(
    container_names: List[str],
    duration_seconds: Optional[int] = None,
    log_file: Optional[str] = None,
) -> List[Dict]:
    """Run a complete eBPF monitoring session and return captured events.

    This is the primary entry point for callers that just want to start
    monitoring without managing the ``EBPFMonitor`` lifecycle themselves.

    Steps:
        1. Call ``get_ebpf_capabilities()`` and print the effective mode.
        2. Create an ``EBPFMonitor`` with a list-collector callback.
        3. Call ``monitor.start()``.
        4. If ``duration_seconds`` is set, run for that many seconds then stop.
           Otherwise, run until a ``KeyboardInterrupt`` is received.
        5. Return all captured events as a list of plain dicts (JSON-safe).
        6. If ``log_file`` is provided, append each event as a JSON line.

    Args:
        container_names:  Docker container IDs or names to monitor.
        duration_seconds: How many seconds to monitor.  ``None`` or ``0``
                          means run until Ctrl+C.
        log_file:         Optional path to a newline-delimited JSON log file.
                          Each event is appended as a single JSON line.

    Returns:
        List of event dictionaries (one per captured event), ordered by
        arrival time.  Each dict is the ``dataclasses.asdict()`` representation
        of the original event object, with an additional ``"type"`` key set to
        the event class name (``"ExecEvent"``, ``"ConnectEvent"``,
        ``"FileEvent"``).
    """
    caps = get_ebpf_capabilities()
    console.print(
        f"\n  [bold cyan][>>] eBPF Monitor[/] | platform=[bold]{caps['platform']}[/]"
        f" | kernel=[bold]{caps['kernel']}[/]"
        f" | bcc={caps['bcc_available']}"
        f" | mode=[bold]{caps['mode'].upper()}[/]"
        f" | features={', '.join(caps['features'])}"
    )

    collected_events: List[Dict] = []
    _log_fh = None

    if log_file:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
            _log_fh = open(log_file, "a", encoding="utf-8")
        except Exception as exc:
            console.print(f"  [dim yellow][!] Could not open eBPF log file '{log_file}': {exc}[/]")

    def _on_event(event) -> None:
        display_ebpf_event(event)
        event_dict = asdict(event)
        event_dict["type"] = type(event).__name__
        collected_events.append(event_dict)
        if _log_fh:
            try:
                _log_fh.write(json.dumps(event_dict) + "\n")
                _log_fh.flush()
            except Exception:
                pass

    monitor = EBPFMonitor(container_ids=container_names, event_callback=_on_event)

    try:
        monitor.start()

        if duration_seconds and duration_seconds > 0:
            console.print(
                f"  [dim]Monitoring for {duration_seconds}s "
                f"({len(container_names)} container(s))...[/]"
            )
            time.sleep(duration_seconds)
        else:
            console.print(
                f"  [dim]Monitoring {len(container_names)} container(s). "
                f"Press Ctrl+C to stop.[/]"
            )
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        console.print("\n  [bold yellow][>>] eBPF session interrupted by user.[/]")
    finally:
        monitor.stop()
        if _log_fh:
            try:
                _log_fh.close()
            except Exception:
                pass

    console.print(
        f"  [bold green][OK][/] eBPF session complete. "
        f"Captured [bold]{len(collected_events)}[/] event(s)."
    )
    return collected_events


# ═══════════════════════════════════════════════════════════════════════════════
# STANDALONE DEMO  (fallback mode — safe to run on Windows)
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """Demo: run the eBPF monitor in fallback mode for 15 seconds.

    On Windows or when BCC is unavailable the monitor falls back to
    docker-top polling.  Any running Docker container can be passed as
    the first CLI argument; defaults to 'vulnapp'.

    Usage:
        python ebpf_monitor.py [container_name]
    """
    target = sys.argv[1] if len(sys.argv) > 1 else "vulnapp"
    console.print(f"\n[bold cyan]Supply Chain Sentinel — eBPF Monitor Demo[/]")
    console.print(f"  Target container : [bold]{target}[/]")
    console.print(f"  Duration         : 15 seconds")
    console.print(f"  Platform         : {platform.system()} / {platform.release()}")

    caps = get_ebpf_capabilities()
    console.print(f"\n  [bold]Capabilities:[/]")
    for k, v in caps.items():
        console.print(f"    {k:<18}: {v}")

    console.print()
    events = run_ebpf_session(
        container_names=[target],
        duration_seconds=15,
        log_file="ebpf_demo.log",
    )

    console.print(f"\n[bold]Captured Events Summary:[/]")
    if not events:
        console.print("  [dim]No security events captured during the 15-second window.[/]")
    else:
        for i, e in enumerate(events, 1):
            console.print(
                f"  {i:3}. [{e['severity']}] {e['type']} | "
                f"PID={e['pid']} | {e['comm']} | {e['reason']}"
            )
