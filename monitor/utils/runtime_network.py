"""
Supply Chain Sentinel — Runtime Network Monitor
=================================================
Captures, decodes, classifies, and alerts on active TCP/UDP sockets
inside running Docker containers by reading the Linux kernel's
/proc/net/tcp, /proc/net/tcp6, and /proc/net/udp pseudo-files.

This module enables DYNAMIC analysis — detecting live exfiltration
channels, C2 callbacks, and cloud-metadata access that static code
analysis alone cannot see.

Key capabilities:
  - Portable: reads /proc/net/* directly (available in every Linux
    container, including distroless images), with automatic fallback
    to `ss` or `netstat` if /proc is restricted.
  - Hex decoder: converts kernel hex-encoded IPs and ports to
    human-readable form.
  - Risk classifier: separates loopback, private/Docker, DNS, cloud
    metadata, and truly external connections.
  - AbuseIPDB integration: optional reputation lookup for external IPs.
"""

import struct
import socket
import subprocess
import re
import json
import math
import time
import urllib.request
import urllib.error
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from fnmatch import fnmatch

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

# TCP states from the Linux kernel (net/tcp_states.h)
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

# Well-known cloud metadata IPs (credential harvesting targets)
METADATA_IPS = {
    "169.254.169.254",      # AWS / GCP / Azure Instance Metadata Service
    "169.254.170.2",        # AWS ECS Task Metadata
    "100.100.100.200",      # Alibaba Cloud Metadata
    "fd00:ec2::254",        # AWS IPv6 metadata
}

# Well-known suspicious ports
SUSPICIOUS_PORTS = {
    4444,     # Metasploit default listener
    5555,     # Common reverse shell
    6666,     # IRC-based C2
    6667,     # IRC
    8443,     # Alternative HTTPS (often C2)
    9001,     # Tor default
    31337,    # "Elite" backdoor port
    1337,     # l33t
    12345,    # NetBus trojan
    65535,    # Often used in PoCs
}

# Risk classification labels
RISK_LOOPBACK = "LOOPBACK"
RISK_PRIVATE = "PRIVATE"
RISK_DOCKER = "DOCKER_INTERNAL"
RISK_DNS = "DNS"
RISK_METADATA = "CLOUD_METADATA"
RISK_EXTERNAL = "EXTERNAL"
RISK_SUSPICIOUS_PORT = "SUSPICIOUS_PORT"
RISK_UNAUTHORIZED_DEST = "UNAUTHORIZED_DEST"
RISK_SUSPICIOUS_DOMAIN = "SUSPICIOUS_DOMAIN"
RISK_DNS_TUNNELING = "DNS_TUNNELING"
RISK_RAW_IP = "RAW_IP_CONNECTION"
RISK_PROCESS_ESCAPE = "PROCESS_ESCAPE"

# Style mapping for risk levels
RISK_STYLES = {
    RISK_LOOPBACK:         "dim",
    RISK_PRIVATE:          "dim cyan",
    RISK_DOCKER:           "dim cyan",
    RISK_DNS:              "dim",
    RISK_METADATA:         "bold white on red",
    RISK_EXTERNAL:         "bold yellow",
    RISK_SUSPICIOUS_PORT:  "bold red",
    RISK_UNAUTHORIZED_DEST: "bold white on dark_orange",
    RISK_SUSPICIOUS_DOMAIN: "bold white on red",
    RISK_DNS_TUNNELING:    "bold white on red",
    RISK_RAW_IP:           "bold red",
    RISK_PROCESS_ESCAPE:   "bold white on red",
}


# ═══════════════════════════════════════════════════════════════
# HEX DECODING — /proc/net/tcp FORMAT
# ═══════════════════════════════════════════════════════════════

def _hex_to_ipv4(hex_ip: str) -> str:
    """
    Convert a little-endian hex string from /proc/net/tcp to a dotted IPv4.

    Example: '0100007F' -> '127.0.0.1'
    The kernel stores IPv4 addresses in network (big-endian) representation
    but /proc/net/tcp displays them as a 32-bit little-endian hex integer.
    """
    try:
        packed = struct.pack("<I", int(hex_ip, 16))
        return socket.inet_ntoa(packed)
    except (ValueError, struct.error, OSError):
        return hex_ip


def _hex_to_ipv6(hex_ip: str) -> str:
    """
    Convert a 32-char hex string from /proc/net/tcp6 to an IPv6 address.

    /proc/net/tcp6 stores IPv6 as four 32-bit little-endian words.
    Example: '00000000000000000000000001000000' -> '::1'
    """
    try:
        if len(hex_ip) != 32:
            return hex_ip
        # Split into four 8-char (32-bit) words, each in little-endian
        words = [hex_ip[i:i+8] for i in range(0, 32, 8)]
        packed = b""
        for word in words:
            packed += struct.pack("<I", int(word, 16))
        return socket.inet_ntop(socket.AF_INET6, packed)
    except (ValueError, struct.error, OSError):
        return hex_ip


def _hex_to_port(hex_port: str) -> int:
    """Convert a hex port string to an integer. Example: '0050' -> 80."""
    try:
        return int(hex_port, 16)
    except ValueError:
        return 0


# ═══════════════════════════════════════════════════════════════
# DOCKER EXEC HELPER
# ═══════════════════════════════════════════════════════════════

def _exec_in_container(container_name: str, command: List[str], timeout: int = 10) -> Optional[str]:
    """Run a command inside a Docker container and return stdout, or None on failure."""
    try:
        cmd = ["docker", "exec", container_name] + command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    return None


# ═══════════════════════════════════════════════════════════════
# PROC/NET PARSER
# ═══════════════════════════════════════════════════════════════

def _parse_proc_net_tcp(raw_output: str, is_ipv6: bool = False) -> List[Dict]:
    """
    Parse the output of /proc/net/tcp or /proc/net/tcp6.

    Each line (after the header) has the format:
      sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
       0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 ...

    Returns a list of socket dicts.
    """
    sockets = []
    lines = raw_output.strip().split("\n")

    for line in lines[1:]:  # Skip the header line
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        try:
            # Local address
            local_addr_hex, local_port_hex = parts[1].split(":")
            # Remote address
            remote_addr_hex, remote_port_hex = parts[2].split(":")
            # State
            state_hex = parts[3]

            if is_ipv6:
                local_ip = _hex_to_ipv6(local_addr_hex)
                remote_ip = _hex_to_ipv6(remote_addr_hex)
            else:
                local_ip = _hex_to_ipv4(local_addr_hex)
                remote_ip = _hex_to_ipv4(remote_addr_hex)

            local_port = _hex_to_port(local_port_hex)
            remote_port = _hex_to_port(remote_port_hex)
            state = TCP_STATES.get(state_hex, f"UNKNOWN({state_hex})")

            sockets.append({
                "protocol": "tcp6" if is_ipv6 else "tcp",
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
            })
        except (ValueError, IndexError):
            continue

    return sockets


def _parse_proc_net_udp(raw_output: str, is_ipv6: bool = False) -> List[Dict]:
    """Parse /proc/net/udp or /proc/net/udp6. Same format as tcp but state is always 07."""
    sockets = []
    lines = raw_output.strip().split("\n")

    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        try:
            local_addr_hex, local_port_hex = parts[1].split(":")
            remote_addr_hex, remote_port_hex = parts[2].split(":")

            if is_ipv6:
                local_ip = _hex_to_ipv6(local_addr_hex)
                remote_ip = _hex_to_ipv6(remote_addr_hex)
            else:
                local_ip = _hex_to_ipv4(local_addr_hex)
                remote_ip = _hex_to_ipv4(remote_addr_hex)

            local_port = _hex_to_port(local_port_hex)
            remote_port = _hex_to_port(remote_port_hex)

            sockets.append({
                "protocol": "udp6" if is_ipv6 else "udp",
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": "UNCONN" if remote_port == 0 else "ACTIVE",
            })
        except (ValueError, IndexError):
            continue

    return sockets


# ═══════════════════════════════════════════════════════════════
# FALLBACK: PARSE ss / netstat OUTPUT
# ═══════════════════════════════════════════════════════════════

def _parse_ss_output(raw_output: str) -> List[Dict]:
    """
    Parse `ss -tunap` output as a fallback when /proc/net is inaccessible.

    Example lines:
      ESTAB  0  0  172.17.0.2:8080  93.184.216.34:443  users:(("node",pid=1,fd=12))
      LISTEN 0  128  0.0.0.0:3000  0.0.0.0:*
    """
    sockets = []
    lines = raw_output.strip().split("\n")

    for line in lines:
        line = line.strip()
        # Skip header lines
        if not line or line.startswith("State") or line.startswith("Netid"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        state = parts[0]
        local_full = parts[3] if len(parts) > 3 else ""
        remote_full = parts[4] if len(parts) > 4 else ""

        # Parse address:port
        local_ip, local_port = _split_address_port(local_full)
        remote_ip, remote_port = _split_address_port(remote_full)

        # Determine protocol from context
        protocol = "tcp"
        if "udp" in line.lower():
            protocol = "udp"

        sockets.append({
            "protocol": protocol,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
        })

    return sockets


def _split_address_port(addr_str: str) -> Tuple[str, int]:
    """Split an address:port string, handling IPv6 brackets."""
    if not addr_str or addr_str == "*":
        return "0.0.0.0", 0

    # IPv6: [::1]:8080
    if addr_str.startswith("["):
        bracket_end = addr_str.rfind("]")
        if bracket_end != -1 and bracket_end + 1 < len(addr_str) and addr_str[bracket_end + 1] == ":":
            ip = addr_str[1:bracket_end]
            try:
                port = int(addr_str[bracket_end + 2:])
            except ValueError:
                port = 0
            return ip, port

    # IPv4 or simple: 0.0.0.0:8080
    last_colon = addr_str.rfind(":")
    if last_colon != -1:
        ip = addr_str[:last_colon]
        port_str = addr_str[last_colon + 1:]
        if port_str == "*":
            return ip, 0
        try:
            port = int(port_str)
        except ValueError:
            port = 0
        return ip, port

    return addr_str, 0


# ═══════════════════════════════════════════════════════════════
# IP CLASSIFICATION
# ═══════════════════════════════════════════════════════════════

def _classify_ip(ip: str) -> str:
    """
    Classify an IP address into a risk category.

    Returns one of the RISK_* constants.
    """
    if not ip or ip in ("0.0.0.0", "*", "::"):
        return RISK_LOOPBACK

    # IPv6 loopback
    if ip == "::1":
        return RISK_LOOPBACK

    # IPv4-mapped IPv6 (::ffff:x.x.x.x) — extract the IPv4 part
    ipv4 = ip
    if ip.startswith("::ffff:"):
        ipv4 = ip[7:]

    # Cloud metadata — TOP PRIORITY (these can be private-range IPs!)
    if ip in METADATA_IPS or ipv4 in METADATA_IPS:
        return RISK_METADATA

    # Parse IPv4 octets
    parts = ipv4.split(".")
    if len(parts) == 4:
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return RISK_EXTERNAL

        # Loopback 127.x.x.x
        if octets[0] == 127:
            return RISK_LOOPBACK

        # Docker default bridge: 172.17.x.x (narrow range for Docker)
        if octets[0] == 172 and octets[1] == 17:
            return RISK_DOCKER

        # Broader private ranges
        if octets[0] == 10:
            return RISK_PRIVATE
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return RISK_PRIVATE
        if octets[0] == 192 and octets[1] == 168:
            return RISK_PRIVATE

        # Link-local (non-metadata)
        if octets[0] == 169 and octets[1] == 254:
            return RISK_PRIVATE

        # Reserved / multicast
        if octets[0] == 0 or octets[0] >= 224:
            return RISK_LOOPBACK

    return RISK_EXTERNAL


def classify_connection(sock: Dict) -> Dict:
    """
    Enrich a socket dict with risk classification for the remote endpoint.

    Adds 'risk' and 'risk_detail' keys.
    """
    remote_ip = sock.get("remote_ip", "0.0.0.0")
    remote_port = sock.get("remote_port", 0)

    risk = _classify_ip(remote_ip)

    # DNS queries (port 53) are benign noise
    if remote_port == 53:
        risk = RISK_DNS

    # Even if the IP is "external", check for suspicious ports
    risk_detail = ""
    if risk == RISK_EXTERNAL and remote_port in SUSPICIOUS_PORTS:
        risk = RISK_SUSPICIOUS_PORT
        risk_detail = f"Port {remote_port} is commonly used by malware/C2 frameworks"
    elif risk == RISK_METADATA:
        risk_detail = "Cloud Instance Metadata Service — potential credential exfiltration"
    elif risk == RISK_EXTERNAL:
        # Provide the well-known port service name if possible
        try:
            service = socket.getservbyport(remote_port, "tcp")
            risk_detail = f"Service: {service}"
        except OSError:
            risk_detail = ""

    sock["risk"] = risk
    sock["risk_detail"] = risk_detail
    return sock


# ═══════════════════════════════════════════════════════════════
# MAIN: GET CONTAINER SOCKETS
# ═══════════════════════════════════════════════════════════════

def get_container_sockets(container_name: str) -> List[Dict]:
    """
    Retrieve all active TCP/UDP sockets from a running Docker container.

    Strategy:
      1. Try /proc/net/tcp  (IPv4 TCP)
      2. Try /proc/net/tcp6 (IPv6 TCP)
      3. Try /proc/net/udp  (IPv4 UDP)
      4. Try /proc/net/udp6 (IPv6 UDP)
      5. Fallback: run `ss -tunap` if /proc is restricted
      6. Last resort: run `netstat -tunap`

    Returns a list of classified socket dicts.
    """
    all_sockets = []
    proc_succeeded = False

    # --- Primary: /proc/net pseudo-files ---
    tcp_raw = _exec_in_container(container_name, ["cat", "/proc/net/tcp"])
    if tcp_raw:
        all_sockets.extend(_parse_proc_net_tcp(tcp_raw, is_ipv6=False))
        proc_succeeded = True

    tcp6_raw = _exec_in_container(container_name, ["cat", "/proc/net/tcp6"])
    if tcp6_raw:
        all_sockets.extend(_parse_proc_net_tcp(tcp6_raw, is_ipv6=True))
        proc_succeeded = True

    udp_raw = _exec_in_container(container_name, ["cat", "/proc/net/udp"])
    if udp_raw:
        all_sockets.extend(_parse_proc_net_udp(udp_raw, is_ipv6=False))
        proc_succeeded = True

    udp6_raw = _exec_in_container(container_name, ["cat", "/proc/net/udp6"])
    if udp6_raw:
        all_sockets.extend(_parse_proc_net_udp(udp6_raw, is_ipv6=True))
        proc_succeeded = True

    # --- Fallback: ss ---
    if not proc_succeeded:
        ss_raw = _exec_in_container(container_name, ["ss", "-tunap"])
        if ss_raw:
            all_sockets.extend(_parse_ss_output(ss_raw))
            proc_succeeded = True

    # --- Last resort: netstat ---
    if not proc_succeeded:
        netstat_raw = _exec_in_container(container_name, ["netstat", "-tunap"])
        if netstat_raw:
            all_sockets.extend(_parse_ss_output(netstat_raw))  # Similar enough format

    # Classify every connection
    for sock in all_sockets:
        classify_connection(sock)

    return all_sockets


# ═══════════════════════════════════════════════════════════════
# ATTRIBUTION — BACKTRACK CONNECTIONS TO PACKAGES
# ═══════════════════════════════════════════════════════════════

def get_network_attribution_logs(container_name: str) -> List[Dict]:
    """
    Read the attribution log written by the preload.js instrumentation
    script from inside the container.

    Returns a list of dicts, each representing one logged outbound
    connection with its attributed package, file, and line number.
    """
    raw = _exec_in_container(container_name, ["cat", "/app/network_attribution.log"], timeout=5)
    if not raw:
        return []

    entries = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            # Skip the startup marker
            if entry.get("protocol") == "SENTINEL":
                continue
            entries.append(entry)
        except (json.JSONDecodeError, ValueError):
            continue

    return entries


def _normalize_host(host: str) -> str:
    """Normalize a hostname for comparison (lowercase, strip trailing dot)."""
    if not host:
        return ""
    return host.lower().rstrip(".")


def _resolve_host_to_ips(host: str) -> List[str]:
    """
    Attempt to resolve a hostname to its IP addresses for matching
    against /proc/net/tcp socket entries (which only show IPs).
    """
    ips = []
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET)
        for result in results:
            ip = result[4][0]
            if ip not in ips:
                ips.append(ip)
    except (socket.gaierror, OSError):
        pass
    return ips


def correlate_attribution(
    sockets: List[Dict],
    attribution_logs: List[Dict],
) -> List[Dict]:
    """
    Enrich socket dicts with attribution data by matching sockets
    against the logged outbound connections from preload.js.

    Matching strategy:
      1. Direct IP match: log entry host == socket remote_ip
      2. DNS resolution: resolve log entry host -> IPs -> match socket remote_ip
      3. Port match: also verify the port matches

    Adds to each matching socket:
      - attributed_package: package name (e.g. 'net-phantom')
      - attributed_file: file path within the package
      - attributed_line: line number
    """
    if not attribution_logs:
        return sockets

    # Build a lookup: (remote_ip, remote_port) -> attribution info
    # We resolve hostnames from log entries to IPs for matching
    ip_port_to_attr = {}
    host_resolution_cache = {}  # hostname -> [ips]

    for entry in attribution_logs:
        host = entry.get("host", "")
        port = entry.get("port", 0)
        pkg = entry.get("package", "unknown")
        file = entry.get("file", "unknown")
        line = entry.get("line", 0)

        if not host or pkg in ("unknown", "sentinel"):
            continue

        # Get IPs for this host
        normalized_host = _normalize_host(host)
        if normalized_host not in host_resolution_cache:
            # Try as direct IP first
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', normalized_host):
                host_resolution_cache[normalized_host] = [normalized_host]
            else:
                resolved = _resolve_host_to_ips(normalized_host)
                host_resolution_cache[normalized_host] = resolved if resolved else []

        ips = host_resolution_cache[normalized_host]

        attr_info = {
            "attributed_package": pkg,
            "attributed_file": file,
            "attributed_line": line,
            "attributed_host": host,
        }

        for ip in ips:
            key = (ip, int(port))
            # Keep the most specific (non-app) attribution
            if key not in ip_port_to_attr or ip_port_to_attr[key]["attributed_package"] == "app":
                ip_port_to_attr[key] = attr_info

        # Also store with just the host as a fallback key (port-only match)
        ip_port_to_attr[(normalized_host, int(port))] = attr_info

    # Now enrich sockets
    for sock in sockets:
        remote_ip = sock.get("remote_ip", "")
        remote_port = sock.get("remote_port", 0)

        # Try exact (ip, port) match
        key = (remote_ip, remote_port)
        if key in ip_port_to_attr:
            sock.update(ip_port_to_attr[key])
            continue

        # Try port-only match against all attribution entries with same port
        for attr_key, attr_val in ip_port_to_attr.items():
            if attr_key[1] == remote_port and attr_val.get("attributed_package") != "app":
                # Check if the IPs from the resolution match
                host = attr_val.get("attributed_host", "")
                normalized = _normalize_host(host)
                if normalized in host_resolution_cache:
                    if remote_ip in host_resolution_cache[normalized]:
                        sock.update(attr_val)
                        break

    return sockets


def get_attribution_summary(attribution_logs: List[Dict]) -> List[Dict]:
    """
    Summarize attribution logs into a per-package breakdown.

    Returns a list of dicts:
      [{ package, file, host, port, count, protocol }, ...]
    """
    # Group by (package, file, host, port)
    groups = {}
    for entry in attribution_logs:
        pkg = entry.get("package", "unknown")
        if pkg in ("unknown", "sentinel"):
            continue
        key = (
            pkg,
            entry.get("file", "?"),
            entry.get("host", "?"),
            entry.get("port", 0),
        )
        if key not in groups:
            groups[key] = {
                "package": pkg,
                "file": entry.get("file", "?"),
                "line": entry.get("line", 0),
                "host": entry.get("host", "?"),
                "port": entry.get("port", 0),
                "protocol": entry.get("protocol", "?"),
                "method": entry.get("method", "?"),
                "count": 0,
            }
        groups[key]["count"] += 1

    return sorted(groups.values(), key=lambda x: (-x["count"], x["package"]))


# ═══════════════════════════════════════════════════════════════
# LAYER 1: OUTBOUND DOMAIN ALLOWLISTING (Zero-Trust)
# ═══════════════════════════════════════════════════════════════

def _domain_matches_allowlist(domain: str, allowlist: List[str]) -> bool:
    """
    Check if a domain matches any entry in the allowlist.
    Supports wildcard patterns: '*.npmjs.org' matches 'registry.npmjs.org'.
    """
    if not domain or not allowlist:
        return False
    domain = domain.lower().rstrip(".")
    for pattern in allowlist:
        pattern = pattern.lower().rstrip(".")
        if fnmatch(domain, pattern):
            return True
        # Also match the domain itself if pattern is *.x.y and domain is x.y
        if pattern.startswith("*.") and domain == pattern[2:]:
            return True
    return False


def check_allowlist_violations(
    attribution_logs: List[Dict],
    allowed_domains: Optional[List[str]] = None,
    allowed_ips: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Evaluate attribution logs against domain/IP allowlists.
    Returns a list of violation dicts for connections to unauthorized destinations.

    Each violation:
      { package, file, line, host, port, protocol, reason }
    """
    from .config import ALLOWED_DOMAINS, ALLOWED_IPS

    if allowed_domains is None:
        allowed_domains = ALLOWED_DOMAINS
    if allowed_ips is None:
        allowed_ips = ALLOWED_IPS

    # If allowlists are explicitly disabled (set to None in config)
    if allowed_domains is None:
        return []

    violations = []
    seen = set()
    ipv4_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    for entry in attribution_logs:
        host = entry.get("host", "")
        port = entry.get("port", 0)
        pkg = entry.get("package", "unknown")
        protocol = entry.get("protocol", "")

        if not host or pkg in ("unknown", "sentinel", "app"):
            continue
        if protocol in ("SENTINEL", "dns"):
            continue

        dedup_key = (pkg, host, port)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Check if it's an IP address
        if ipv4_re.match(host):
            if host not in (allowed_ips or []):
                # Check if this is a private/loopback IP (allow those)
                risk = _classify_ip(host)
                if risk in (RISK_LOOPBACK, RISK_PRIVATE, RISK_DOCKER, RISK_DNS):
                    continue
                violations.append({
                    "package": pkg,
                    "file": entry.get("file", "?"),
                    "line": entry.get("line", 0),
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "reason": f"IP {host} not in allowed IP list",
                })
        else:
            # It's a domain
            if not _domain_matches_allowlist(host, allowed_domains):
                violations.append({
                    "package": pkg,
                    "file": entry.get("file", "?"),
                    "line": entry.get("line", 0),
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "reason": f"Domain '{host}' not in allowed domain list",
                })

    return violations


# ═══════════════════════════════════════════════════════════════
# LAYER 2: DOMAIN AGE VERIFICATION (RDAP WHOIS)
# ═══════════════════════════════════════════════════════════════

def _load_whois_cache() -> Dict:
    """Load the local WHOIS cache from disk."""
    from .config import WHOIS_CACHE_FILE
    try:
        with open(WHOIS_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _save_whois_cache(cache: Dict):
    """Save the WHOIS cache to disk."""
    from .config import WHOIS_CACHE_FILE
    try:
        with open(WHOIS_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except OSError:
        pass


def _extract_registrable_domain(host: str) -> str:
    """
    Extract the registrable domain from a hostname.
    e.g., 'c2-staging.nexustools.dev' -> 'nexustools.dev'
    Simple heuristic: take last 2 parts (or 3 for co.uk etc.)
    """
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return host.lower()
    # Handle common multi-part TLDs
    multi_tlds = {"co.uk", "com.au", "co.jp", "com.br", "org.uk", "co.in"}
    if len(parts) >= 3:
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in multi_tlds:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def query_domain_age(domain: str) -> Optional[Dict]:
    """
    Query the RDAP bootstrap server for domain registration date.
    Returns { 'domain': str, 'registration_date': str, 'age_days': int }
    or None if the query fails.
    """
    from .config import RDAP_BOOTSTRAP_URL, RDAP_TIMEOUT

    registrable = _extract_registrable_domain(domain)
    url = f"{RDAP_BOOTSTRAP_URL}{registrable}"

    try:
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))

        # Find the registration event
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            if action in ("registration", "created"):
                reg_date_str = event.get("eventDate", "")
                if reg_date_str:
                    reg_date = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    age_days = (now - reg_date).days
                    return {
                        "domain": registrable,
                        "registration_date": reg_date_str,
                        "age_days": age_days,
                    }
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            ValueError, OSError, KeyError, TypeError):
        pass

    return None


def check_domain_ages(
    attribution_logs: List[Dict],
    suspicious_age_days: Optional[int] = None,
) -> List[Dict]:
    """
    Check domain registration ages for all external hosts in attribution logs.
    Returns a list of suspicious domain dicts (recently registered).

    Each entry:
      { package, file, line, host, domain, registration_date, age_days, reason }
    """
    from .config import SUSPICIOUS_DOMAIN_AGE_DAYS, RDAP_RATE_LIMIT_DELAY

    if suspicious_age_days is None:
        suspicious_age_days = SUSPICIOUS_DOMAIN_AGE_DAYS

    # Collect unique external domains
    ipv4_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    domain_to_entries = {}  # registrable_domain -> [log_entries]

    for entry in attribution_logs:
        host = entry.get("host", "")
        pkg = entry.get("package", "unknown")
        protocol = entry.get("protocol", "")

        if not host or pkg in ("unknown", "sentinel", "app"):
            continue
        if protocol in ("SENTINEL", "dns"):
            continue
        if ipv4_re.match(host):
            continue  # Skip raw IPs

        registrable = _extract_registrable_domain(host)
        if registrable not in domain_to_entries:
            domain_to_entries[registrable] = []
        domain_to_entries[registrable].append(entry)

    if not domain_to_entries:
        return []

    # Load cache
    cache = _load_whois_cache()
    suspicious = []
    cache_updated = False

    for domain, entries in domain_to_entries.items():
        # Check cache first
        if domain in cache:
            age_info = cache[domain]
        else:
            age_info = query_domain_age(domain)
            if age_info:
                cache[domain] = age_info
                cache_updated = True
            time.sleep(RDAP_RATE_LIMIT_DELAY)

        if age_info and age_info.get("age_days", 9999) < suspicious_age_days:
            # Flag all entries for this domain
            for entry in entries:
                suspicious.append({
                    "package": entry.get("package", "?"),
                    "file": entry.get("file", "?"),
                    "line": entry.get("line", 0),
                    "host": entry.get("host", "?"),
                    "domain": domain,
                    "registration_date": age_info.get("registration_date", "?"),
                    "age_days": age_info.get("age_days", 0),
                    "reason": f"Domain '{domain}' registered only {age_info['age_days']} days ago (threshold: {suspicious_age_days})",
                })

    # Save updated cache
    if cache_updated:
        _save_whois_cache(cache)

    return suspicious


# ═══════════════════════════════════════════════════════════════
# LAYER 3: DNS TUNNELING & VOLUME DETECTION
# ═══════════════════════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def check_dns_tunneling(attribution_logs: List[Dict]) -> List[Dict]:
    """
    Analyze DNS queries from attribution logs for tunneling indicators:
    1. Burst detection: a single package making many DNS queries in a short window
    2. Entropy detection: subdomain strings with unusually high entropy (encoded data)

    Returns a list of anomaly dicts:
      { package, file, host, anomaly_type, detail }
    """
    from .config import (
        DNS_BURST_THRESHOLD,
        DNS_BURST_WINDOW_SECONDS,
        DNS_SUBDOMAIN_LEN_LIMIT,
        DNS_ENTROPY_THRESHOLD,
    )

    # Filter to DNS-only entries
    dns_entries = [
        e for e in attribution_logs
        if e.get("protocol") == "dns"
        and e.get("package") not in ("unknown", "sentinel", "app")
    ]

    if not dns_entries:
        return []

    anomalies = []
    seen = set()

    # ── Burst Detection ──
    # Group DNS queries by package
    pkg_dns = {}
    for entry in dns_entries:
        pkg = entry.get("package", "?")
        if pkg not in pkg_dns:
            pkg_dns[pkg] = []
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", "").replace("Z", "+00:00"))
            pkg_dns[pkg].append((ts, entry))
        except (ValueError, TypeError):
            pkg_dns[pkg].append((datetime.now(timezone.utc), entry))

    for pkg, timed_entries in pkg_dns.items():
        if len(timed_entries) >= DNS_BURST_THRESHOLD:
            # Sort by time and check sliding window
            timed_entries.sort(key=lambda x: x[0])
            window_start = 0
            for window_end in range(len(timed_entries)):
                while (timed_entries[window_end][0] - timed_entries[window_start][0]).total_seconds() > DNS_BURST_WINDOW_SECONDS:
                    window_start += 1
                window_size = window_end - window_start + 1
                if window_size >= DNS_BURST_THRESHOLD:
                    burst_key = f"burst:{pkg}"
                    if burst_key not in seen:
                        seen.add(burst_key)
                        anomalies.append({
                            "package": pkg,
                            "file": timed_entries[window_end][1].get("file", "?"),
                            "host": f"{window_size} queries in {DNS_BURST_WINDOW_SECONDS}s",
                            "anomaly_type": "DNS_BURST",
                            "detail": f"Package '{pkg}' made {window_size} DNS queries within {DNS_BURST_WINDOW_SECONDS}s (threshold: {DNS_BURST_THRESHOLD})",
                        })
                    break

    # ── High-Entropy Subdomain Detection ──
    for entry in dns_entries:
        host = entry.get("host", "")
        pkg = entry.get("package", "?")

        if not host:
            continue

        parts = host.split(".")
        if len(parts) < 3:
            continue  # Need at least sub.domain.tld

        # Check each subdomain label (excluding the registrable domain)
        for label in parts[:-2]:
            entropy_key = f"entropy:{pkg}:{label}"
            if entropy_key in seen:
                continue

            if len(label) > DNS_SUBDOMAIN_LEN_LIMIT:
                seen.add(entropy_key)
                anomalies.append({
                    "package": pkg,
                    "file": entry.get("file", "?"),
                    "host": host,
                    "anomaly_type": "LONG_SUBDOMAIN",
                    "detail": f"Subdomain label '{label[:30]}...' is {len(label)} chars (limit: {DNS_SUBDOMAIN_LEN_LIMIT}). Possible data exfiltration via DNS.",
                })
            elif _shannon_entropy(label) > DNS_ENTROPY_THRESHOLD and len(label) > 12:
                seen.add(entropy_key)
                anomalies.append({
                    "package": pkg,
                    "file": entry.get("file", "?"),
                    "host": host,
                    "anomaly_type": "HIGH_ENTROPY_SUBDOMAIN",
                    "detail": f"Subdomain '{label[:30]}' has high entropy ({_shannon_entropy(label):.2f} > {DNS_ENTROPY_THRESHOLD}). Possible DNS tunneling.",
                })

    return anomalies


# ═══════════════════════════════════════════════════════════════
# LAYER 4: RAW IP CONNECTION DETECTION
# ═══════════════════════════════════════════════════════════════

def check_raw_ip_connections(attribution_logs: List[Dict]) -> List[Dict]:
    """
    Detect packages that connect directly to raw IP addresses (bypassing DNS).
    Legitimate traffic almost always uses domain names; raw IPs suggest hardcoded
    C2 infrastructure.

    Returns a list of raw IP connection dicts:
      { package, file, line, host, port, protocol, reason }
    """
    ipv4_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    raw_ip_hits = []
    seen = set()

    for entry in attribution_logs:
        host = entry.get("host", "")
        pkg = entry.get("package", "unknown")
        port = entry.get("port", 0)
        protocol = entry.get("protocol", "")
        is_raw = entry.get("is_raw_ip", False)

        if not host or pkg in ("unknown", "sentinel", "app"):
            continue
        if protocol in ("SENTINEL", "dns"):
            continue

        # Check if the host is a raw IP (either flagged by preload or detected here)
        if is_raw or ipv4_re.match(host):
            # Skip loopback and private IPs
            risk = _classify_ip(host)
            if risk in (RISK_LOOPBACK, RISK_PRIVATE, RISK_DOCKER, RISK_DNS):
                continue

            dedup_key = (pkg, host, port)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            raw_ip_hits.append({
                "package": pkg,
                "file": entry.get("file", "?"),
                "line": entry.get("line", 0),
                "host": host,
                "port": port,
                "protocol": protocol,
                "reason": f"Package '{pkg}' connects directly to raw IP {host}:{port} (bypasses DNS)",
            })

    return raw_ip_hits


# ═══════════════════════════════════════════════════════════════
# LAYER 5: PROCESS ESCAPE DETECTION (Shell Execution)
# ═══════════════════════════════════════════════════════════════

def check_process_escapes(attribution_logs: List[Dict]) -> List[Dict]:
    """
    Detect packages that spawn child processes (exec, spawn, fork, etc.).
    Malicious packages often shell out to `curl`, `wget`, `bash`, or `nc`
    to exfiltrate data or download second-stage payloads, bypassing the
    Node.js network hooks entirely.

    Returns a list of process escape dicts:
      { package, file, line, command, args, method, severity, reason }
    """
    process_escapes = []
    seen = set()

    for entry in attribution_logs:
        protocol = entry.get("protocol", "")
        pkg = entry.get("package", "unknown")

        if protocol != "child_process":
            continue
        if pkg in ("unknown", "sentinel", "app"):
            continue

        command = entry.get("host", "")
        args = entry.get("path", "")
        method = entry.get("method", "")
        severity = entry.get("severity", "LOW")
        is_suspicious = entry.get("is_suspicious", False)

        dedup_key = (pkg, command, method)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Build descriptive reason based on severity
        if severity == "CRITICAL":
            reason = f"CRITICAL: Package '{pkg}' spawned network tool '{command}' via {method}() -- likely data exfiltration"
        elif severity == "HIGH":
            reason = f"HIGH: Package '{pkg}' opened a shell '{command}' via {method}() -- arbitrary code execution"
        elif severity == "MEDIUM":
            reason = f"MEDIUM: Package '{pkg}' ran encoding tool '{command}' via {method}() -- may process stolen data"
        else:
            reason = f"LOW: Package '{pkg}' spawned subprocess '{command}' via {method}()"

        process_escapes.append({
            "package": pkg,
            "file": entry.get("file", "?"),
            "line": entry.get("line", 0),
            "command": command,
            "args": args,
            "method": method,
            "severity": severity,
            "is_suspicious": is_suspicious,
            "reason": reason,
        })

    return process_escapes


# ═══════════════════════════════════════════════════════════════
# UNIFIED EVASION ANALYSIS
# ═══════════════════════════════════════════════════════════════

def run_evasion_analysis(
    attribution_logs: List[Dict],
) -> Dict:
    """
    Run all five evasion detection layers on the attribution logs.

    Returns a dict with all findings:
    {
        "allowlist_violations": [...],
        "suspicious_domains": [...],
        "dns_anomalies": [...],
        "raw_ip_connections": [...],
        "process_escapes": [...],
        "total_findings": int,
    }
    """
    console.print(f"  [dim]Running Zero-Day Evasion Analysis (5 layers)...[/]")

    # Layer 1: Allowlist
    allowlist_violations = check_allowlist_violations(attribution_logs)
    if allowlist_violations:
        console.print(f"  [bold dark_orange][!!] Layer 1: {len(allowlist_violations)} unauthorized destination(s)[/]")
    else:
        console.print(f"  [bold green][OK] Layer 1: All destinations match allowlist[/]")

    # Layer 2: Domain Age
    suspicious_domains = check_domain_ages(attribution_logs)
    if suspicious_domains:
        console.print(f"  [bold red][!!] Layer 2: {len(suspicious_domains)} recently-registered domain(s)[/]")
    else:
        console.print(f"  [bold green][OK] Layer 2: No suspicious domain ages detected[/]")

    # Layer 3: DNS Tunneling
    dns_anomalies = check_dns_tunneling(attribution_logs)
    if dns_anomalies:
        console.print(f"  [bold red][!!] Layer 3: {len(dns_anomalies)} DNS anomaly(s) detected[/]")
    else:
        console.print(f"  [bold green][OK] Layer 3: No DNS tunneling indicators[/]")

    # Layer 4: Raw IP
    raw_ip_connections = check_raw_ip_connections(attribution_logs)
    if raw_ip_connections:
        console.print(f"  [bold red][!!] Layer 4: {len(raw_ip_connections)} raw IP connection(s)[/]")
    else:
        console.print(f"  [bold green][OK] Layer 4: No raw IP connections detected[/]")

    # Layer 5: Process Escapes
    process_escapes = check_process_escapes(attribution_logs)
    if process_escapes:
        critical = sum(1 for p in process_escapes if p.get('severity') == 'CRITICAL')
        high = sum(1 for p in process_escapes if p.get('severity') == 'HIGH')
        console.print(f"  [bold white on red][!!!] Layer 5: {len(process_escapes)} process escape(s) ({critical} critical, {high} high)[/]")
    else:
        console.print(f"  [bold green][OK] Layer 5: No process escapes detected[/]")

    total = len(allowlist_violations) + len(suspicious_domains) + len(dns_anomalies) + len(raw_ip_connections) + len(process_escapes)

    return {
        "allowlist_violations": allowlist_violations,
        "suspicious_domains": suspicious_domains,
        "dns_anomalies": dns_anomalies,
        "raw_ip_connections": raw_ip_connections,
        "process_escapes": process_escapes,
        "total_findings": total,
    }


def display_evasion_report(container_name: str, evasion_results: Dict):
    """
    Display a comprehensive evasion detection report using Rich tables.
    """
    total = evasion_results.get("total_findings", 0)
    if total == 0:
        console.print(Panel(
            "[bold green][OK] Zero-Day Evasion Analysis: No findings across all 4 layers.[/]",
            title=f"[bold green]Evasion Analysis: {container_name}[/]",
            border_style="green",
            padding=(1, 2),
        ))
        return

    # ── Layer 1: Allowlist Violations ──
    violations = evasion_results.get("allowlist_violations", [])
    if violations:
        viol_table = Table(
            show_header=True,
            header_style="bold white on dark_orange",
            border_style="dark_orange",
            show_lines=True,
            padding=(0, 1),
            expand=False,
        )
        viol_table.add_column("#", style="dim", width=4, justify="right")
        viol_table.add_column("Package", style="bold red", min_width=18)
        viol_table.add_column("File:Line", style="cyan", min_width=20)
        viol_table.add_column("Unauthorized Host", style="bold yellow", min_width=25)
        viol_table.add_column("Port", style="white", width=6, justify="right")
        viol_table.add_column("Reason", min_width=30)

        for idx, v in enumerate(violations, 1):
            file_line = f"{v['file']}:{v['line']}" if v.get('line') else v.get('file', '?')
            viol_table.add_row(
                str(idx), v["package"], file_line,
                v["host"], str(v["port"]), v["reason"],
            )

        console.print(Panel(
            viol_table,
            title=f"[bold dark_orange][!!] LAYER 1 - UNAUTHORIZED DESTINATIONS: {container_name}[/]",
            border_style="dark_orange",
            padding=(0, 1),
        ))

    # ── Layer 2: Suspicious Domains ──
    sus_domains = evasion_results.get("suspicious_domains", [])
    if sus_domains:
        dom_table = Table(
            show_header=True,
            header_style="bold white on red",
            border_style="red",
            show_lines=True,
            padding=(0, 1),
            expand=False,
        )
        dom_table.add_column("#", style="dim", width=4, justify="right")
        dom_table.add_column("Package", style="bold red", min_width=18)
        dom_table.add_column("Domain", style="bold yellow", min_width=25)
        dom_table.add_column("Registered", style="white", min_width=20)
        dom_table.add_column("Age (days)", style="bold red", width=10, justify="right")
        dom_table.add_column("Verdict", min_width=20)

        seen_doms = set()
        idx = 0
        for d in sus_domains:
            dom_key = (d["package"], d["domain"])
            if dom_key in seen_doms:
                continue
            seen_doms.add(dom_key)
            idx += 1
            dom_table.add_row(
                str(idx), d["package"], d["domain"],
                d.get("registration_date", "?")[:10],
                str(d["age_days"]),
                f"[bold red]NEWLY REGISTERED[/]",
            )

        console.print(Panel(
            dom_table,
            title=f"[bold red][!!!] LAYER 2 - SUSPICIOUS DOMAIN AGE: {container_name}[/]",
            border_style="red",
            padding=(0, 1),
        ))

    # ── Layer 3: DNS Anomalies ──
    dns_anom = evasion_results.get("dns_anomalies", [])
    if dns_anom:
        dns_table = Table(
            show_header=True,
            header_style="bold white on red",
            border_style="red",
            show_lines=True,
            padding=(0, 1),
            expand=False,
        )
        dns_table.add_column("#", style="dim", width=4, justify="right")
        dns_table.add_column("Package", style="bold red", min_width=18)
        dns_table.add_column("Anomaly", style="bold yellow", min_width=20)
        dns_table.add_column("Host/Detail", style="white", min_width=30)
        dns_table.add_column("Description", min_width=40)

        for idx, a in enumerate(dns_anom, 1):
            dns_table.add_row(
                str(idx), a["package"], a["anomaly_type"],
                a.get("host", "?")[:40], a["detail"][:60],
            )

        console.print(Panel(
            dns_table,
            title=f"[bold red][!!!] LAYER 3 - DNS TUNNELING INDICATORS: {container_name}[/]",
            border_style="red",
            padding=(0, 1),
        ))

    # ── Layer 4: Raw IP Connections ──
    raw_ips = evasion_results.get("raw_ip_connections", [])
    if raw_ips:
        raw_table = Table(
            show_header=True,
            header_style="bold white on red",
            border_style="red",
            show_lines=True,
            padding=(0, 1),
            expand=False,
        )
        raw_table.add_column("#", style="dim", width=4, justify="right")
        raw_table.add_column("Package", style="bold red", min_width=18)
        raw_table.add_column("File:Line", style="cyan", min_width=20)
        raw_table.add_column("Raw IP", style="bold yellow", min_width=18)
        raw_table.add_column("Port", style="white", width=6, justify="right")
        raw_table.add_column("Reason", min_width=35)

        for idx, r in enumerate(raw_ips, 1):
            file_line = f"{r['file']}:{r['line']}" if r.get('line') else r.get('file', '?')
            raw_table.add_row(
                str(idx), r["package"], file_line,
                r["host"], str(r["port"]), r["reason"][:50],
            )

        console.print(Panel(
            raw_table,
            title=f"[bold red][!!!] LAYER 4 - RAW IP CONNECTIONS (DNS Bypass): {container_name}[/]",
            border_style="red",
            padding=(0, 1),
        ))

    # ── Layer 5: Process Escapes ──
    proc_escapes = evasion_results.get("process_escapes", [])
    if proc_escapes:
        proc_table = Table(
            show_header=True,
            header_style="bold white on red",
            border_style="red",
            show_lines=True,
            padding=(0, 1),
            expand=False,
        )
        proc_table.add_column("#", style="dim", width=4, justify="right")
        proc_table.add_column("Severity", min_width=10)
        proc_table.add_column("Package", style="bold red", min_width=18)
        proc_table.add_column("File:Line", style="cyan", min_width=20)
        proc_table.add_column("Method", style="white", min_width=10)
        proc_table.add_column("Command", style="bold yellow", min_width=25)
        proc_table.add_column("Arguments", min_width=20)

        severity_styles = {
            "CRITICAL": "bold white on red",
            "HIGH": "bold red",
            "MEDIUM": "bold dark_orange",
            "LOW": "bold yellow",
        }

        for idx, p in enumerate(proc_escapes, 1):
            sev = p.get("severity", "LOW")
            sev_style = severity_styles.get(sev, "white")
            file_line = f"{p['file']}:{p['line']}" if p.get('line') else p.get('file', '?')
            proc_table.add_row(
                str(idx),
                f"[{sev_style}]{sev}[/]",
                p["package"],
                file_line,
                p.get("method", "?"),
                p.get("command", "?")[:40],
                p.get("args", "")[:30],
            )

        console.print(Panel(
            proc_table,
            title=f"[bold white on red][!!!!] LAYER 5 - PROCESS ESCAPES (Shell Execution): {container_name}[/]",
            border_style="red",
            padding=(0, 1),
        ))


# ═══════════════════════════════════════════════════════════════
# FILTERING & AGGREGATION
# ═══════════════════════════════════════════════════════════════

def filter_interesting_sockets(sockets: List[Dict]) -> List[Dict]:
    """
    Filter out pure noise (loopback, DNS, LISTEN on 0.0.0.0)
    and return only connections worth reporting.
    """
    interesting = []
    for sock in sockets:
        risk = sock.get("risk", RISK_LOOPBACK)

        # Always skip loopback and plain DNS
        if risk in (RISK_LOOPBACK, RISK_DNS):
            continue

        # Skip LISTEN sockets on wildcard addresses (server is listening, not connecting out)
        if sock.get("state") == "LISTEN" and sock.get("remote_ip") in ("0.0.0.0", "::", "*"):
            continue

        # Skip UNCONN (unconnected UDP) with no remote
        if sock.get("state") == "UNCONN" and sock.get("remote_port", 0) == 0:
            continue

        interesting.append(sock)

    return interesting


def get_threat_sockets(sockets: List[Dict]) -> List[Dict]:
    """Return only sockets that pose a genuine security concern."""
    threats = []
    threat_risks = {
        RISK_METADATA, RISK_SUSPICIOUS_PORT, RISK_EXTERNAL,
        RISK_UNAUTHORIZED_DEST, RISK_SUSPICIOUS_DOMAIN,
        RISK_DNS_TUNNELING, RISK_RAW_IP, RISK_PROCESS_ESCAPE,
    }
    for sock in sockets:
        risk = sock.get("risk", "")
        if risk in threat_risks:
            # For external, only flag ESTABLISHED or SYN_SENT (active connections)
            if risk == RISK_EXTERNAL:
                if sock.get("state") in ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "ACTIVE"):
                    threats.append(sock)
            else:
                threats.append(sock)
    return threats


def summarize_sockets(sockets: List[Dict]) -> Dict:
    """
    Build a summary report of all sockets grouped by risk category.

    Returns:
        {
            "total": int,
            "by_risk": { risk_label: [sockets] },
            "by_state": { state: count },
            "threat_count": int,
            "listening_ports": [port_numbers],
        }
    """
    by_risk = {}
    by_state = {}
    listening_ports = set()

    for sock in sockets:
        risk = sock.get("risk", "UNKNOWN")
        state = sock.get("state", "UNKNOWN")

        by_risk.setdefault(risk, []).append(sock)
        by_state[state] = by_state.get(state, 0) + 1

        if state == "LISTEN":
            listening_ports.add(sock.get("local_port", 0))

    threats = get_threat_sockets(sockets)

    return {
        "total": len(sockets),
        "by_risk": by_risk,
        "by_state": by_state,
        "threat_count": len(threats),
        "threat_sockets": threats,
        "listening_ports": sorted(listening_ports),
    }


# ═══════════════════════════════════════════════════════════════
# DISPLAY — RICH CONSOLE OUTPUT
# ═══════════════════════════════════════════════════════════════

def display_network_report(container_name: str, sockets: List[Dict], compact: bool = False):
    """
    Print a comprehensive network connections report for a container.

    Args:
        container_name: The Docker container name.
        sockets: List of classified socket dicts from get_container_sockets().
        compact: If True, only show threats (for watch mode).
    """
    if not sockets:
        console.print(Panel(
            "[bold green][OK] No network sockets detected in container.[/]",
            title=f"[bold cyan]Network Monitor: {container_name}[/]",
            border_style="green",
            padding=(1, 2),
        ))
        return

    summary = summarize_sockets(sockets)
    interesting = filter_interesting_sockets(sockets)
    threats = summary["threat_sockets"]

    # ── Summary Stats ──
    stats_table = Table(show_header=False, border_style="cyan", padding=(0, 2), expand=False)
    stats_table.add_column("Metric", style="bold cyan", min_width=25)
    stats_table.add_column("Value", style="bold white")

    stats_table.add_row("Total Sockets", str(summary["total"]))
    stats_table.add_row("Listening Ports", ", ".join(str(p) for p in summary["listening_ports"]) or "None")
    stats_table.add_row("Active External Connections",
                        f"[bold yellow]{len(summary['by_risk'].get(RISK_EXTERNAL, []))}[/]")
    stats_table.add_row("Metadata Access Attempts",
                        f"[bold red]{len(summary['by_risk'].get(RISK_METADATA, []))}[/]")
    stats_table.add_row("Suspicious Port Connections",
                        f"[bold red]{len(summary['by_risk'].get(RISK_SUSPICIOUS_PORT, []))}[/]")

    # State breakdown
    state_parts = []
    for state, count in sorted(summary["by_state"].items()):
        if state == "ESTABLISHED":
            state_parts.append(f"[bold green]{state}: {count}[/]")
        elif state in ("SYN_SENT", "SYN_RECV"):
            state_parts.append(f"[bold yellow]{state}: {count}[/]")
        elif state == "LISTEN":
            state_parts.append(f"[dim]{state}: {count}[/]")
        else:
            state_parts.append(f"{state}: {count}")
    stats_table.add_row("Socket States", "  ".join(state_parts) if state_parts else "None")

    console.print(Panel(
        stats_table,
        title=f"[bold cyan]Network Summary: {container_name}[/]",
        border_style="cyan",
        padding=(1, 2),
    ))

    # ── Threat Alert Panel ──
    if threats:
        threat_table = Table(
            show_header=True,
            header_style="bold white on red",
            border_style="red",
            show_lines=True,
            padding=(0, 1),
            expand=False,
        )
        threat_table.add_column("#", style="dim", width=4, justify="right")
        threat_table.add_column("Proto", style="bold white", justify="center", width=6)
        threat_table.add_column("Local", style="cyan", min_width=20)
        threat_table.add_column("Remote", style="bold yellow", min_width=22)
        threat_table.add_column("State", justify="center", min_width=12)
        threat_table.add_column("Risk", justify="center", min_width=16)
        threat_table.add_column("Detail", min_width=30)

        for idx, sock in enumerate(threats, 1):
            risk = sock.get("risk", "")
            risk_style = RISK_STYLES.get(risk, "white")

            local_str = f"{sock['local_ip']}:{sock['local_port']}"
            remote_str = f"{sock['remote_ip']}:{sock['remote_port']}"

            risk_display = Text(risk, style=risk_style)
            detail = sock.get("risk_detail", "")

            threat_table.add_row(
                str(idx),
                sock["protocol"].upper(),
                local_str,
                remote_str,
                sock.get("state", "?"),
                risk_display,
                detail,
            )

        console.print(Panel(
            threat_table,
            title=f"[bold red][!!!] NETWORK THREAT ALERT: {container_name}[/]",
            border_style="red",
            padding=(0, 1),
        ))
    else:
        console.print(f"  [bold green][OK] No suspicious network connections detected.[/]")

    # ── Attribution Table (if attribution data is available) ──
    attributed_sockets = [s for s in sockets if s.get("attributed_package")]
    if attributed_sockets and not compact:
        attr_table = Table(
            show_header=True,
            header_style="bold white on dark_magenta",
            border_style="magenta",
            show_lines=True,
            padding=(0, 1),
            expand=False,
        )
        attr_table.add_column("#", style="dim", width=4, justify="right")
        attr_table.add_column("Remote", style="bold yellow", min_width=22)
        attr_table.add_column("State", justify="center", min_width=10)
        attr_table.add_column("Package", style="bold red", min_width=18)
        attr_table.add_column("File:Line", style="cyan", min_width=25)

        seen = set()
        idx = 0
        for sock in attributed_sockets:
            pkg = sock.get("attributed_package", "?")
            file = sock.get("attributed_file", "?")
            line = sock.get("attributed_line", 0)
            remote_str = f"{sock['remote_ip']}:{sock['remote_port']}"
            dedup_key = (remote_str, pkg, file)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            idx += 1

            file_line = f"{file}:{line}" if line else file

            attr_table.add_row(
                str(idx),
                remote_str,
                sock.get("state", "?"),
                pkg,
                file_line,
            )

        console.print(Panel(
            attr_table,
            title=f"[bold magenta][>>] CONNECTION ATTRIBUTION: {container_name}[/]",
            border_style="magenta",
            padding=(0, 1),
        ))

    # ── Full Connections Table (non-compact mode only) ──
    if not compact and interesting:
        conn_table = Table(
            show_header=True,
            header_style="bold white on dark_blue",
            border_style="blue",
            show_lines=False,
            padding=(0, 1),
            expand=False,
        )
        conn_table.add_column("#", style="dim", width=4, justify="right")
        conn_table.add_column("Proto", style="bold white", justify="center", width=6)
        conn_table.add_column("Local Address", style="cyan", min_width=22)
        conn_table.add_column("Remote Address", style="white", min_width=22)
        conn_table.add_column("State", justify="center", min_width=12)
        conn_table.add_column("Classification", justify="center", min_width=16)

        for idx, sock in enumerate(interesting, 1):
            risk = sock.get("risk", "")
            risk_style = RISK_STYLES.get(risk, "white")

            local_str = f"{sock['local_ip']}:{sock['local_port']}"
            remote_str = f"{sock['remote_ip']}:{sock['remote_port']}"

            conn_table.add_row(
                str(idx),
                sock["protocol"].upper(),
                local_str,
                remote_str,
                sock.get("state", "?"),
                Text(risk, style=risk_style),
            )

        console.print(Panel(
            conn_table,
            title=f"[bold blue]All Active Connections: {container_name}[/]",
            border_style="blue",
            padding=(0, 1),
        ))


def display_attribution_summary(container_name: str, attribution_logs: List[Dict]):
    """
    Display a standalone summary of all packages that made outbound
    network calls, with call counts, targets, and file locations.
    """
    summary = get_attribution_summary(attribution_logs)
    if not summary:
        return

    # Filter out 'app' entries to focus on dependency packages
    pkg_entries = [s for s in summary if s["package"] != "app"]
    if not pkg_entries:
        return

    attr_sum_table = Table(
        show_header=True,
        header_style="bold white on dark_magenta",
        border_style="magenta",
        show_lines=True,
        padding=(0, 1),
        expand=False,
    )
    attr_sum_table.add_column("#", style="dim", width=4, justify="right")
    attr_sum_table.add_column("Package", style="bold red", min_width=18)
    attr_sum_table.add_column("File:Line", style="cyan", min_width=22)
    attr_sum_table.add_column("Target Host", style="bold yellow", min_width=20)
    attr_sum_table.add_column("Port", style="white", width=6, justify="right")
    attr_sum_table.add_column("Proto", style="white", width=6, justify="center")
    attr_sum_table.add_column("Calls", style="bold white", width=6, justify="right")

    for idx, entry in enumerate(pkg_entries, 1):
        file_line = f"{entry['file']}:{entry['line']}" if entry['line'] else entry['file']
        attr_sum_table.add_row(
            str(idx),
            entry["package"],
            file_line,
            entry["host"],
            str(entry["port"]),
            entry["protocol"].upper(),
            str(entry["count"]),
        )

    console.print(Panel(
        attr_sum_table,
        title=f"[bold magenta][>>] PACKAGE NETWORK ATTRIBUTION LOG: {container_name}[/]",
        border_style="magenta",
        padding=(0, 1),
    ))

