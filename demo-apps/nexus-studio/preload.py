"""
Supply Chain Sentinel -- Python Runtime Attribution Preload
=============================================================
This script is loaded automatically via sitecustomize.py (PYTHONPATH=/app)
before ANY Python application code runs inside the container.

It uses sys.addaudithook (Python 3.8+) to intercept:
  - os.system / subprocess calls (process escapes)
  - socket.connect (outbound network connections)
  - open() on sensitive files (credential theft)

Output: JSON-lines appended to /app/network_attribution.log
        (same file and schema as preload.cjs so the Sentinel
         monitor can process both Node.js and Python events
         with zero changes)

SAFETY: This script is designed for monitoring/auditing only.
        It does NOT block, modify, or intercept any traffic.
"""

import sys
import os
import json
import traceback
import datetime
import re

# ── Configuration ──
LOG_FILE = "/app/network_attribution.log"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB rotation threshold
MAX_ENTRIES = 2000

_entry_count = 0
_inside_hook = False  # Re-entrancy guard

# ── Suspicious command patterns ──
SUSPICIOUS_COMMANDS = {
    "curl", "wget", "nc", "ncat", "bash", "sh", "zsh",
    "powershell", "cmd", "certutil", "python", "python3",
    "ruby", "perl", "php", "nslookup", "dig", "telnet",
}

# ── Sensitive environment keys ──
SENSITIVE_ENV_KEYS = {
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
    "NPM_TOKEN", "DATABASE_URL", "JWT_SECRET", "SECRET_KEY",
    "PRIVATE_KEY", "API_KEY", "DOCKER_PASSWORD", "SLACK_TOKEN",
    "STRIPE_SECRET_KEY", "GOOGLE_API_KEY",
}

# ── Sensitive file paths ──
SENSITIVE_FILES = {
    "/etc/passwd", "/etc/shadow", ".ssh/id_rsa", ".ssh/id_ed25519",
    ".aws/credentials", ".npmrc", ".env", ".git/config",
    "/proc/self/environ",
}


# ═══════════════════════════════════════════════════════════════
# LOG WRITER (matches preload.cjs JSON-lines schema exactly)
# ═══════════════════════════════════════════════════════════════

def _write_attribution(entry):
    """Append a structured JSON line to the shared attribution log."""
    global _entry_count
    if _entry_count >= MAX_ENTRIES:
        return

    try:
        # Rotate if too large
        try:
            stat = os.stat(LOG_FILE)
            if stat.st_size > MAX_LOG_SIZE:
                os.rename(LOG_FILE, LOG_FILE + ".old")
        except OSError:
            pass

        line = json.dumps(entry, default=str) + "\n"
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
        _entry_count += 1
    except Exception:
        pass  # Never crash the host application


# ═══════════════════════════════════════════════════════════════
# STACK TRACE PARSER (Python equivalent of parseCallOrigin)
# ═══════════════════════════════════════════════════════════════

def _parse_call_origin():
    """Walk the Python call stack to find the originating package."""
    result = {
        "package": "unknown",
        "file": "unknown",
        "line": 0,
        "stack_frame": "",
    }

    try:
        frames = traceback.extract_stack()

        for frame in reversed(frames):
            filepath = frame.filename or ""

            # Skip our own hook and stdlib internals
            if "sitecustomize" in filepath or "preload.py" in filepath:
                continue
            if filepath.startswith("<") and filepath.endswith(">"):
                continue

            # Check for site-packages (pip installed packages)
            match = re.search(r"site-packages[/\\]([^/\\]+)", filepath)
            if match:
                pkg_name = match.group(1)
                # Normalize dist-info / egg-info dirs
                pkg_name = re.sub(r"[-.].*", "", pkg_name)
                result["package"] = pkg_name
                result["file"] = filepath.split("site-packages" + os.sep)[-1] if "site-packages" in filepath else filepath
                result["line"] = frame.lineno or 0
                result["stack_frame"] = f"  at {frame.name} ({filepath}:{frame.lineno})"
                return result

            # Check for demo-packages (our local test packages)
            match = re.search(r"demo-packages[/\\]([^/\\]+)", filepath)
            if match:
                result["package"] = match.group(1)
                result["file"] = filepath.split("demo-packages" + os.sep)[-1] if "demo-packages" in filepath else filepath
                result["line"] = frame.lineno or 0
                result["stack_frame"] = f"  at {frame.name} ({filepath}:{frame.lineno})"
                return result

            # If it's inside /app/ but not a known package, label as 'app'
            if "/app/" in filepath:
                result["package"] = "app"
                result["file"] = filepath
                result["line"] = frame.lineno or 0
                result["stack_frame"] = f"  at {frame.name} ({filepath}:{frame.lineno})"
                return result

    except Exception:
        pass

    return result


# ═══════════════════════════════════════════════════════════════
# COMMAND SEVERITY CLASSIFIER
# ═══════════════════════════════════════════════════════════════

def _classify_command(cmd_str):
    """Classify command severity (matches preload.cjs logic)."""
    if not cmd_str:
        return "LOW"
    cmd_lower = cmd_str.lower()
    first_token = cmd_lower.split()[0] if cmd_lower.split() else ""
    base = os.path.basename(first_token)

    # CRITICAL: network exfil tools or piped shell execution
    critical_indicators = ["curl", "wget", "nc", "ncat", "telnet", "| bash", "| sh"]
    for indicator in critical_indicators:
        if indicator in cmd_lower:
            return "CRITICAL"

    # HIGH: shell interpreters
    if base in ("bash", "sh", "zsh", "powershell", "cmd"):
        return "HIGH"

    # MEDIUM: scripting languages
    if base in ("python", "python3", "ruby", "perl", "php", "node"):
        return "MEDIUM"

    return "LOW"


# ═══════════════════════════════════════════════════════════════
# THE AUDIT HOOK (core interception engine)
# ═══════════════════════════════════════════════════════════════

def _sentinel_audit_hook(event, args):
    """Python audit hook that intercepts security-relevant events."""
    global _inside_hook

    # Prevent infinite recursion (our own log writes trigger audit events)
    if _inside_hook:
        return
    _inside_hook = True

    try:
        # ── 1. Process Execution (os.system) ──
        if event == "os.system":
            cmd_str = args[0] if args else ""
            origin = _parse_call_origin()
            severity = _classify_command(cmd_str)

            _write_attribution({
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "protocol": "child_process",
                "host": str(cmd_str)[:200],
                "port": 0,
                "path": "",
                "method": "os.system",
                "severity": severity,
                "is_suspicious": any(sc in str(cmd_str).lower() for sc in SUSPICIOUS_COMMANDS),
                "package": origin["package"],
                "file": origin["file"],
                "line": origin["line"],
                "stack_frame": origin["stack_frame"],
            })

        # ── 2. Process Execution (subprocess) ──
        elif event == "subprocess.Popen":
            executable = args[0] if args else []
            if isinstance(executable, (list, tuple)):
                cmd_str = " ".join(str(a) for a in executable)
                first_cmd = str(executable[0]) if executable else ""
            else:
                cmd_str = str(executable)
                first_cmd = cmd_str

            origin = _parse_call_origin()
            severity = _classify_command(cmd_str)

            _write_attribution({
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "protocol": "child_process",
                "host": first_cmd[:200],
                "port": 0,
                "path": cmd_str[:300],
                "method": "subprocess.Popen",
                "severity": severity,
                "is_suspicious": any(sc in cmd_str.lower() for sc in SUSPICIOUS_COMMANDS),
                "package": origin["package"],
                "file": origin["file"],
                "line": origin["line"],
                "stack_frame": origin["stack_frame"],
            })

        # ── 3. Network Connections (socket.connect) ──
        elif event == "socket.connect":
            # args = (socket_obj, address)
            # address is typically (host, port) for AF_INET
            if args and len(args) >= 2:
                address = args[1] if len(args) > 1 else args[0]
                if isinstance(address, tuple) and len(address) >= 2:
                    host, port = str(address[0]), int(address[1])
                    origin = _parse_call_origin()

                    _write_attribution({
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                        "protocol": "tcp",
                        "host": host[:200],
                        "port": port,
                        "path": "",
                        "method": "socket.connect",
                        "package": origin["package"],
                        "file": origin["file"],
                        "line": origin["line"],
                        "stack_frame": origin["stack_frame"],
                    })

        # ── 4. Sensitive File Access (open) ──
        elif event == "open":
            if args:
                filepath = str(args[0])
                # Only log if it's a sensitive file
                is_sensitive = any(sf in filepath for sf in SENSITIVE_FILES)
                if is_sensitive:
                    origin = _parse_call_origin()

                    _write_attribution({
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                        "protocol": "file_access",
                        "host": filepath[:200],
                        "port": 0,
                        "path": filepath,
                        "method": "open",
                        "severity": "HIGH",
                        "is_suspicious": True,
                        "package": origin["package"],
                        "file": origin["file"],
                        "line": origin["line"],
                        "stack_frame": origin["stack_frame"],
                    })

        # ── 5. Dynamic Code Execution (exec/eval/compile) ──
        elif event in ("exec", "compile"):
            origin = _parse_call_origin()
            # Only log if it comes from a third-party package
            if origin["package"] not in ("unknown", "app", "sentinel"):
                _write_attribution({
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "protocol": "child_process",
                    "host": event,
                    "port": 0,
                    "path": f"dynamic code execution via {event}()",
                    "method": event,
                    "severity": "HIGH",
                    "is_suspicious": True,
                    "package": origin["package"],
                    "file": origin["file"],
                    "line": origin["line"],
                    "stack_frame": origin["stack_frame"],
                })

    except Exception:
        pass  # Never crash the host application
    finally:
        _inside_hook = False


# ═══════════════════════════════════════════════════════════════
# INITIALIZE
# ═══════════════════════════════════════════════════════════════

try:
    sys.addaudithook(_sentinel_audit_hook)

    # Write startup marker (same format as preload.cjs)
    _write_attribution({
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "protocol": "SENTINEL",
        "host": "preload-init",
        "port": 0,
        "path": "",
        "method": "STARTUP",
        "package": "sentinel",
        "file": "preload.py (sitecustomize)",
        "line": 0,
        "stack_frame": "Supply Chain Sentinel Python Attribution Engine initialized (v1: Process+Network+FileAccess+DynExec)",
    })
except Exception:
    pass  # If sys.addaudithook is unavailable (Python < 3.8), fail silently
