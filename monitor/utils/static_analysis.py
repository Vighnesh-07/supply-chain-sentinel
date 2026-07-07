"""
Supply Chain Sentinel — Static Analysis & IOC Extraction
============================================================
Scans installed package source files to extract Indicators of Compromise:
  - URLs  (http:// and https://)
  - IPv4 addresses
  - Base64-encoded strings  (with entropy + length heuristics)

Extracted IPs are checked against the AbuseIPDB reputation database.

This module is invoked automatically when a package is flagged as malicious
by the threat-intel engine, but can also be run on any package directory.
"""

import base64
import math
import os
import re
import time
import subprocess
import tempfile
from typing import Dict, List, Set, Tuple

import requests

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markup import escape

from .config import (
    step_header,
    ABUSEIPDB_API_URL,
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_RATE_LIMIT_DELAY,
    VIRUSTOTAL_API_URL,
    VIRUSTOTAL_API_KEY,
    VIRUSTOTAL_RATE_LIMIT_DELAY,
    REQUEST_TIMEOUT,
)
from .ast_scanner import scan_file_ast

console = Console()


# ═══════════════════════════════════════════════════════════════
# REGEX PATTERNS
# ═══════════════════════════════════════════════════════════════

# Match http:// and https:// URLs (avoids trailing quotes/parens)
URL_PATTERN = re.compile(
    r'https?://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
    re.IGNORECASE,
)

# Match IPv4 addresses (basic, will filter out obvious non-IPs later)
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)

# Match potential Base64 strings — require min 32 chars to cut noise significantly
BASE64_PATTERN = re.compile(
    r'(?<=["\'\'\s=:,(\[{])([A-Za-z0-9+/]{32,}={0,2})(?=["\'\'\s,)\]}]|$)',
    re.MULTILINE,
)

# Match hex-escaped sequences (e.g. \x41\x42...)
HEX_ESCAPE_PATTERN = re.compile(
    r'(?:\\x[0-9a-fA-F]{2}){4,}'
)

# Match Firebase indicators
FIREBASE_URL_PATTERN = re.compile(
    r'[a-zA-Z0-9-]+\.firebaseio\.com',
    re.IGNORECASE
)
FIREBASE_KEY_PATTERN = re.compile(
    r'AIzaSy[A-Za-z0-9-_]{33}'
)

# Match S3 Buckets / URLs
S3_BUCKET_PATTERN = re.compile(
    r'(?:s3://[a-zA-Z0-9.-]+|[a-zA-Z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com|s3\.amazonaws\.com/[a-zA-Z0-9.-]+)',
    re.IGNORECASE
)

# Match GCP bucket and Azure Blob storage
CLOUD_STORAGE_PATTERN = re.compile(
    r'(?:storage\.googleapis\.com/[a-zA-Z0-9.-]+|gs://[a-zA-Z0-9.-]+|[a-zA-Z0-9.-]+\.blob\.core\.windows\.net)',
    re.IGNORECASE
)

# Match Slack/Discord webhooks
WEBHOOK_PATTERN = re.compile(
    r'(?:https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}|https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+)',
    re.IGNORECASE
)

# Match credential patterns (Private keys, JWTs, Tokens)
CREDENTIAL_PATTERN = re.compile(
    r'(?:BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY|'
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|'
    r'gh[po]_[a-zA-Z0-9]{36}|'
    r'xox[baprs]-[0-9]{10,}-[a-zA-Z0-9]{24}|'
    r'AKIA[0-9A-Z]{16})',
    re.IGNORECASE
)

# Match cryptocurrency wallet addresses
BTC_LEGACY_PATTERN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')  # Legacy P2PKH/P2SH
BTC_BECH32_PATTERN = re.compile(r'\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b')  # Native SegWit (Bech32)
ETH_PATTERN = re.compile(r'\b0x[0-9a-fA-F]{40}\b')  # Ethereum
XMR_PATTERN = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')  # Monero
LTC_PATTERN = re.compile(r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{25,34}\b')  # Litecoin

# Match high-entropy strings that look like API keys/secrets
# These are generic patterns for strings that are too random to be normal code
GENERIC_SECRET_PATTERN = re.compile(
    r'(?:api[_-]?key|api[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|private[_-]?key)'
    r'\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{24,})["\']',
    re.IGNORECASE
)

# File extensions to scan — production source code only, no docs
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".rb", ".go", ".rs", ".php", ".cs", ".java", ".kt",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini",
    ".sh", ".bash", ".bat", ".ps1", ".env",
}

# Directories and file name patterns to skip (tests, docs, examples)
SKIP_DIRS = {
    "__pycache__", ".git", "node_modules", ".tox", ".eggs",
    "dist", "build", "test", "tests", "testing", "spec", "specs",
    "docs", "doc", "documentation", "examples", "example",
    "fixtures", "testdata", "samples", "demo",
}
SKIP_FILE_PATTERNS = re.compile(
    r'(test_|_test|tests?\.py$|spec\.py$|conftest\.py$|setup\.py$'
    r'|setup\.cfg$|changelog|readme|license|authors|copying)',
    re.IGNORECASE,
)

# IPs to ignore (localhost, metadata services, common non-malicious)
BENIGN_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "169.254.169.254",  # AWS/cloud metadata
    "10.0.0.0", "172.16.0.0", "192.168.0.0",  # Private range anchors
}

# URL domains to ignore — extended list covering documentation, bug trackers, standards
BENIGN_URL_DOMAINS = {
    # Code hosting
    "github.com", "gitlab.com", "bitbucket.org", "raw.githubusercontent.com",
    "gist.github.com", "codeberg.org", "sourceforge.net",
    # Package registries & Homepages
    "pypi.org", "files.pythonhosted.org", "npmjs.com", "registry.npmjs.org", "npmjs.org",
    "rubygems.org", "crates.io", "packagist.org", "nuget.org",
    "pkg.go.dev", "golang.org", "gopkg.in", "search.maven.org",
    "pypa.io", "react.dev", "reactjs.org", "expressjs.com", "vite.dev",
    # Docs & language sites
    "docs.python.org", "python.org", "nodejs.org", "ruby-lang.org",
    "rust-lang.org", "kotlinlang.org", "cpython.org",
    "readthedocs.io", "readthedocs.org",
    # Bug trackers & Forums
    "bugs.python.org", "bugs.launchpad.net", "bugzilla.mozilla.org",
    "sourceware.org", "bz.apache.org", "issues.apache.org",
    "jira.atlassian.com", "tracker.debian.org", "stackoverflow.com", "stackexchange.com",
    # Standards, specs, & Corporate docs
    "mozilla.org", "w3.org", "schema.org", "wikipedia.org",
    "json-schema.org", "yaml.org", "ietf.org", "rfc-editor.org",
    "creativecommons.org", "opensource.org",
    "spdx.org", "cyclonedx.org", "owasp.org",
    "microsoft.com", "apple.com", "linuxfoundation.org", "freedesktop.org",
    "stanford.edu", "brew.sh", "activestate.com", "metacpan.org",
    "opencollective.com", "dub.sh",
    # Source code mirrors
    "sqlite.org", "openssl.org", "zlib.net", "libexpat.github.io",
    "heptapod.net", "foss.heptapod.net",
    # Known benign
    "example.com", "example.org", "example.net",
    "localhost", "test.example.com",
    # CI/CD
    "travis-ci.org", "travis-ci.com", "circleci.com",
    "github.io", "codecov.io", "coveralls.io",
    "appveyor.com", "semaphoreci.com",
    # CDN / package delivery
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
}

# Max file size to scan (skip very large files)
MAX_FILE_SIZE = 512 * 1024  # 512 KB


# ═══════════════════════════════════════════════════════════════
# SHANNON ENTROPY (for Base64 validation)
# ═══════════════════════════════════════════════════════════════

def _shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# Regex: detect CamelCase/PascalCase identifiers (class names, type names etc.)
# e.g. "AsyncSingleThreadContext", "UnsupportedOperation"
_IDENTIFIER_RE = re.compile(r'^[A-Z][a-z]+(?:[A-Z][a-z0-9]+)+$')
# Regex: detect ALL_CAPS_CONSTANTS
_CAPS_CONST_RE = re.compile(r'^[A-Z][A-Z0-9_]{4,}$')
# Common short base64 alphabet words to skip
_COMMON_WORDS_RE = re.compile(r'^[A-Za-z]{10,}$')  # All-alpha strings are almost never real b64


def _is_likely_base64(candidate: str) -> bool:
    """
    Heuristic check: is this string likely a Base64-encoded payload?

    Criteria (all must pass):
      - Length >= 32 characters
      - Shannon entropy >= 4.5 (raised threshold to reduce false positives)
      - Not a CamelCase/PascalCase identifier (class names etc.)
      - Not an all-alpha string (dictionary words have low entropy when decoded)
      - Successfully decodes as Base64
      - Decoded bytes contain non-printable characters (real binary/encrypted data)
        OR decoded length > 32 and is > 30% non-printable
    """
    if len(candidate) < 32:
        return False

    # Skip obvious identifiers: PascalCase class names
    if _IDENTIFIER_RE.match(candidate):
        return False

    # Skip ALL_CAPS constants
    if _CAPS_CONST_RE.match(candidate):
        return False

    # Skip all-alpha strings (very unlikely to be real base64 payload)
    if _COMMON_WORDS_RE.match(candidate):
        return False

    # Must have '+' or '/' or '=' for it to look like real base64
    # (pure alphanumeric could just be a hash or identifier)
    has_b64_chars = '+' in candidate or '/' in candidate or candidate.endswith('=')
    if not has_b64_chars and len(candidate) < 64:
        return False

    entropy = _shannon_entropy(candidate)
    if entropy < 4.5:
        return False

    try:
        decoded = base64.b64decode(candidate, validate=True)
        if len(decoded) < 16:
            return False
            
        decoded_text = decoded.decode("utf-8", errors="replace")
        if URL_PATTERN.search(decoded_text) or CREDENTIAL_PATTERN.search(decoded_text):
            return True
            
        # Require significant non-printable content (real binary/cipher data)
        non_printable = sum(1 for b in decoded if not (32 <= b <= 126))
        non_printable_ratio = non_printable / len(decoded)
        # Real encoded payloads typically have >20% non-printable when decoded
        if non_printable_ratio < 0.20:
            return False
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# IP FILTERING
# ═══════════════════════════════════════════════════════════════

def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return True

    # Private ranges
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    # Loopback
    if octets[0] == 127:
        return True
    # Link-local
    if octets[0] == 169 and octets[1] == 254:
        return True
    # Reserved
    if octets[0] == 0 or octets[0] >= 224:
        return True

    return False


def _extract_domain_from_url(url: str) -> str:
    """Extract domain from a URL for filtering."""
    try:
        # Remove protocol
        domain = url.split("://", 1)[1] if "://" in url else url
        # Remove path
        domain = domain.split("/")[0]
        # Remove port
        domain = domain.split(":")[0]
        return domain.lower()
    except (IndexError, AttributeError):
        return ""


# ═══════════════════════════════════════════════════════════════
# FILE SCANNER
# ═══════════════════════════════════════════════════════════════

def scan_package_files(package_path: str) -> Dict:
    """
    Recursively scan all source files in a package directory for IOCs.

    Args:
        package_path: Absolute path to the package directory.

    Returns:
        Dict with keys:
          - urls: list of suspicious URLs found
          - ips: list of suspicious IP addresses found
          - base64_strings: list of suspicious Base64 strings found
          - file_count: number of files scanned
          - ioc_files: dict mapping filename -> list of IOC types found in it
    """
    results = {
        "urls": [],
        "ips": [],
        "base64_strings": [],
        "hex_strings": [],
        "firebase_findings": [],
        "s3_buckets": [],
        "sensitive_strings": [],
        "ast_findings": [],
        "crypto_wallets": [],
        "high_entropy_secrets": [],
        "file_count": 0,
        "ioc_files": {},
    }

    if not os.path.isdir(package_path):
        return results

    seen_urls: Set[str] = set()
    seen_ips: Set[str] = set()
    seen_b64: Set[str] = set()
    seen_hex: Set[str] = set()
    seen_firebase: Set[str] = set()
    seen_s3: Set[str] = set()
    seen_crypto: Set[str] = set()
    seen_secrets: Set[str] = set()
    seen_cloud: Set[str] = set()

    for root, dirs, files in os.walk(package_path):
        # Skip non-source and test/doc directories
        dirs[:] = [
            d for d in dirs
            if d.lower() not in SKIP_DIRS
            and not d.endswith(".egg-info")
        ]

        for filename in files:
            filepath = os.path.join(root, filename)
            ext = os.path.splitext(filename)[1].lower()

            if ext not in SCANNABLE_EXTENSIONS:
                continue

            # Skip test, doc, setup, changelog files by name
            if SKIP_FILE_PATTERNS.search(filename):
                continue

            try:
                file_size = os.path.getsize(filepath)
                if file_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, PermissionError):
                continue

            # Strip comment lines before URL scanning to avoid false positives
            # from docstrings and inline comments
            lines = content.splitlines()
            code_lines = []
            for line in lines:
                stripped = line.lstrip()
                # Skip pure comment lines (Python # and // style)
                if stripped.startswith('#') or stripped.startswith('//'):
                    continue
                # Skip docstring lines (common pattern: line is just a URL in triple-quote)
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    code_lines.append(line)
                    continue
                code_lines.append(line)
            scannable_content = '\n'.join(code_lines)

            results["file_count"] += 1
            file_iocs = []
            rel_path = os.path.relpath(filepath, package_path)

            # ── AST Scanning ──
            ast_results = scan_file_ast(filepath, content)
            if ast_results:
                for res in ast_results:
                    res["file"] = rel_path
                results["ast_findings"].extend(ast_results)
                if "AST" not in file_iocs:
                    file_iocs.append("AST")

            # ── Extract URLs (from code lines only, not comments) ──
            for match in URL_PATTERN.finditer(scannable_content):
                url = match.group(0).rstrip(".,;:)<\"'")
                domain = _extract_domain_from_url(url)
                # Skip benign top-level domains
                if any(domain == d or domain.endswith('.' + d) for d in BENIGN_URL_DOMAINS):
                    continue
                if url not in seen_urls:
                    seen_urls.add(url)
                    results["urls"].append({
                        "value": url,
                        "file": rel_path,
                        "line": content[:match.start()].count("\n") + 1,
                    })
                    if "URL" not in file_iocs:
                        file_iocs.append("URL")

            # ── Extract IPs (from full content, not just code lines) ──
            for match in IPV4_PATTERN.finditer(content):
                ip = match.group(0)
                if ip in BENIGN_IPS or ip in seen_ips:
                    continue
                if _is_private_ip(ip):
                    continue
                seen_ips.add(ip)
                results["ips"].append({
                    "value": ip,
                    "file": rel_path,
                    "line": content[:match.start()].count("\n") + 1,
                })
                if "IP" not in file_iocs:
                    file_iocs.append("IP")

            # ── Extract Base64 (from code lines only) ──
            for match in BASE64_PATTERN.finditer(scannable_content):
                candidate = match.group(1)
                if candidate in seen_b64:
                    continue
                if _is_likely_base64(candidate):
                    seen_b64.add(candidate)
                    # Truncate for display
                    display_val = candidate[:60] + "..." if len(candidate) > 60 else candidate
                    decoded_preview = "<binary data>"
                    contains_url = False
                    contains_cred = False
                    try:
                        decoded_bytes = base64.b64decode(candidate, validate=True)
                        decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                        decoded_preview = decoded_text[:80]
                        
                        if URL_PATTERN.search(decoded_text):
                            contains_url = True
                            for u_match in URL_PATTERN.finditer(decoded_text):
                                u = u_match.group(0).rstrip(".,;:)<\"'")
                                dom = _extract_domain_from_url(u)
                                if not any(dom == d or dom.endswith('.' + d) for d in BENIGN_URL_DOMAINS):
                                    if u not in seen_urls:
                                        seen_urls.add(u)
                                        results["urls"].append({
                                            "value": u,
                                            "file": rel_path + " (in Base64)",
                                            "line": content[:match.start()].count("\n") + 1,
                                         })
                        
                        if CREDENTIAL_PATTERN.search(decoded_text):
                            contains_cred = True
                    except Exception:
                        pass
                    
                    results["base64_strings"].append({
                        "value": display_val,
                        "decoded_preview": decoded_preview,
                        "contains_url": contains_url,
                        "contains_cred": contains_cred,
                        "file": rel_path,
                        "line": content[:match.start()].count("\n") + 1,
                    })
                    if "Base64" not in file_iocs:
                        file_iocs.append("Base64")

            # ── Extract Hexcode (from code lines only) ──
            for match in HEX_ESCAPE_PATTERN.finditer(scannable_content):
                candidate = match.group(0)
                if candidate not in seen_hex:
                    seen_hex.add(candidate)
                    results["hex_strings"].append({
                        "value": candidate,
                        "file": rel_path,
                        "line": content[:match.start()].count("\n") + 1,
                    })
                    if "Hexcode" not in file_iocs:
                        file_iocs.append("Hexcode")

            # ── Extract Firebase Findings ──
            for match in FIREBASE_URL_PATTERN.finditer(scannable_content):
                val = match.group(0)
                if val not in seen_firebase:
                    seen_firebase.add(val)
                    results["firebase_findings"].append({
                        "value": val,
                        "type": "Firebase URL",
                        "file": rel_path,
                        "line": content[:match.start()].count("\n") + 1,
                    })
                    if "Firebase" not in file_iocs:
                        file_iocs.append("Firebase")
            for match in FIREBASE_KEY_PATTERN.finditer(scannable_content):
                val = match.group(0)
                if val not in seen_firebase:
                    seen_firebase.add(val)
                    results["firebase_findings"].append({
                        "value": val,
                        "type": "Firebase API Key",
                        "file": rel_path,
                        "line": content[:match.start()].count("\n") + 1,
                    })
                    if "Firebase" not in file_iocs:
                        file_iocs.append("Firebase")

            # ── Extract S3 Buckets ──
            for match in S3_BUCKET_PATTERN.finditer(scannable_content):
                val = match.group(0)
                if val not in seen_s3:
                    seen_s3.add(val)
                    results["s3_buckets"].append({
                        "value": val,
                        "file": rel_path,
                        "line": content[:match.start()].count("\n") + 1,
                    })
                    if "S3 Bucket" not in file_iocs:
                        file_iocs.append("S3 Bucket")

            # ── Extract Cloud Assets & Webhooks ──
            for match in CLOUD_STORAGE_PATTERN.finditer(scannable_content):
                val = match.group(0)
                if val not in seen_cloud:
                    seen_cloud.add(val)
                    asset_type = "Azure Blob" if "blob.core.windows.net" in val.lower() else "GCS Bucket"
                    results["sensitive_strings"].append({
                        "value": val,
                        "type": asset_type,
                        "file": rel_path,
                        "line": content[:match.start()].count("\n") + 1,
                    })
                    if "Cloud Asset" not in file_iocs:
                        file_iocs.append("Cloud Asset")
            for match in WEBHOOK_PATTERN.finditer(scannable_content):
                val = match.group(0)
                if val not in seen_cloud:
                    seen_cloud.add(val)
                    webhook_type = "Slack Webhook" if "slack.com" in val.lower() else "Discord Webhook"
                    results["sensitive_strings"].append({
                        "value": val,
                        "type": webhook_type,
                        "file": rel_path,
                        "line": content[:match.start()].count("\n") + 1,
                    })
                    if "Webhook" not in file_iocs:
                        file_iocs.append("Webhook")

            # ── Extract Cryptocurrency Wallet Addresses ──
            crypto_patterns = [
                (BTC_LEGACY_PATTERN, "Bitcoin (Legacy)"),
                (BTC_BECH32_PATTERN, "Bitcoin (Bech32)"),
                (ETH_PATTERN, "Ethereum"),
                (XMR_PATTERN, "Monero"),
                (LTC_PATTERN, "Litecoin"),
            ]
            for pattern, wallet_type in crypto_patterns:
                for match in pattern.finditer(scannable_content):
                    val = match.group(0)
                    if val not in seen_crypto:
                        seen_crypto.add(val)
                        results["crypto_wallets"].append({
                            "value": val,
                            "type": wallet_type,
                            "file": rel_path,
                            "line": content[:match.start()].count("\n") + 1,
                        })
                        if "Crypto Wallet" not in file_iocs:
                            file_iocs.append("Crypto Wallet")

            # ── Extract High-Entropy Secrets ──
            for match in GENERIC_SECRET_PATTERN.finditer(scannable_content):
                secret_val = match.group(1)
                if secret_val not in seen_secrets and len(secret_val) > 24:
                    entropy = _shannon_entropy(secret_val)
                    if entropy > 4.5:
                        seen_secrets.add(secret_val)
                        # Extract the key name from the full match for context
                        full_match = match.group(0)
                        context = full_match.split("=")[0].split(":")[0].strip().strip("\"'")
                        truncated = secret_val[:40] + "..." if len(secret_val) > 40 else secret_val
                        results["high_entropy_secrets"].append({
                            "value": truncated,
                            "context": context,
                            "entropy": round(entropy, 2),
                            "file": rel_path,
                            "line": content[:match.start()].count("\n") + 1,
                        })
                        if "Secret" not in file_iocs:
                            file_iocs.append("Secret")

            if file_iocs:
                results["ioc_files"][rel_path] = file_iocs

    return results


# ═══════════════════════════════════════════════════════════════
# ABUSEIPDB REPUTATION CHECK
# ═══════════════════════════════════════════════════════════════

_ABUSEIPDB_CACHE: Dict[str, Dict] = {}

def check_abuseipdb(ip_address: str) -> Dict:
    """
    Query the AbuseIPDB API to check the reputation of an IP address.

    Args:
        ip_address: The IPv4 address to check.

    Returns:
        Dict with keys:
          - ip: the queried IP
          - abuse_confidence_score: 0-100 (100 = definitely malicious)
          - total_reports: number of abuse reports
          - country_code: country of origin
          - isp: ISP name
          - is_public: whether the IP is public
          - error: error message if any
    """
    if ip_address in _ABUSEIPDB_CACHE:
        return _ABUSEIPDB_CACHE[ip_address]

    result = {
        "ip": ip_address,
        "abuse_confidence_score": -1,
        "total_reports": 0,
        "country_code": "??",
        "isp": "Unknown",
        "is_public": True,
        "error": "",
    }

    if not ABUSEIPDB_API_KEY:
        result["error"] = "No API key configured"
        return result

    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": "",
        }
        response = requests.get(
            ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            result["abuse_confidence_score"] = data.get("abuseConfidenceScore", 0)
            result["total_reports"] = data.get("totalReports", 0)
            result["country_code"] = data.get("countryCode", "??")
            result["isp"] = data.get("isp", "Unknown")
            result["is_public"] = data.get("isPublic", True)
        elif response.status_code == 401:
            result["error"] = "Invalid API key"
        elif response.status_code == 429:
            result["error"] = "Rate limited"
        else:
            result["error"] = f"HTTP {response.status_code}"

    except Exception as e:
        result["error"] = str(e)[:80]

    if not result.get("error"):
        _ABUSEIPDB_CACHE[ip_address] = result

    return result


# ═══════════════════════════════════════════════════════════════
# VIRUSTOTAL REPUTATION CHECK
# ═══════════════════════════════════════════════════════════════

_VT_CACHE: Dict[str, Dict] = {}

def check_virustotal_url(url: str) -> Dict:
    """
    Query VirusTotal v3 API to check the reputation of a URL.
    """
    if url in _VT_CACHE:
        return _VT_CACHE[url]

    result = {
        "url": url,
        "malicious_votes": 0,
        "total_votes": 0,
        "error": "",
    }
    
    if not VIRUSTOTAL_API_KEY:
        result["error"] = "No API key configured"
        return result
        
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json",
        }
        
        response = requests.get(
            f"{VIRUSTOTAL_API_URL}/{url_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result["malicious_votes"] = data.get("malicious", 0) + data.get("suspicious", 0)
            result["total_votes"] = sum(data.values())
        elif response.status_code == 401:
            result["error"] = "Invalid API key"
        elif response.status_code == 404:
            result["error"] = "Unscanned URL"
        elif response.status_code == 429:
            result["error"] = "Rate limited"
        else:
            result["error"] = f"HTTP {response.status_code}"
    except Exception as e:
        result["error"] = str(e)[:80]
        
    if not result.get("error"):
        _VT_CACHE[url] = result
        
    return result

# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR: SCAN + CHECK
# ═══════════════════════════════════════════════════════════════

def deep_inspect_package(
    package_name: str,
    package_path: str,
    check_abuse_db: bool = True,
    check_vt: bool = True,
) -> Dict:
    """
    Perform deep static inspection of an installed package:
      1. Scan all source files for URLs, IPs, Base64 strings
      2. Check extracted IPs against AbuseIPDB
      3. Check extracted URLs against VirusTotal

    Args:
        package_name: Human-readable package name.
        package_path: Absolute path to the installed package directory.
        check_abuse_db: Whether to query AbuseIPDB for extracted IPs.
        check_vt: Whether to query VirusTotal for extracted URLs.

    Returns:
        Dict with keys:
          - package: package name
          - path: scanned path
          - scan_results: output from scan_package_files()
          - abuseipdb_results: list of AbuseIPDB check results (one per IP)
          - virustotal_results: list of VirusTotal check results (one per URL)
          - risk_summary: short human-readable risk summary string
    """
    inspection = {
        "package": package_name,
        "path": package_path,
        "scan_results": {},
        "abuseipdb_results": [],
        "virustotal_results": [],
        "risk_summary": "",
    }

    # Step 1: Scan files
    scan = scan_package_files(package_path)
    inspection["scan_results"] = scan

    total_iocs = (
        len(scan["urls"]) +
        len(scan["ips"]) +
        len(scan["base64_strings"]) +
        len(scan.get("hex_strings", [])) +
        len(scan.get("firebase_findings", [])) +
        len(scan.get("s3_buckets", [])) +
        len(scan.get("sensitive_strings", [])) +
        len(scan.get("ast_findings", [])) +
        len(scan.get("crypto_wallets", [])) +
        len(scan.get("high_entropy_secrets", []))
    )

    if total_iocs == 0:
        inspection["risk_summary"] = "No IOCs found"
        return inspection

    # Step 2: Check IPs against AbuseIPDB (Cap at 5 per package)
    if check_abuse_db and scan["ips"]:
        for ip_entry in scan["ips"][:5]:
            ip = ip_entry["value"]
            was_cached = ip in _ABUSEIPDB_CACHE
            abuse_result = check_abuseipdb(ip)
            inspection["abuseipdb_results"].append(abuse_result)
            if not was_cached and ABUSEIPDB_API_KEY:
                time.sleep(ABUSEIPDB_RATE_LIMIT_DELAY)

    # Step 3: Check URLs against VirusTotal (Cap at 5 per package)
    if check_vt and scan["urls"]:
        for url_entry in scan["urls"][:5]:
            url = url_entry["value"]
            was_cached = url in _VT_CACHE
            vt_result = check_virustotal_url(url)
            inspection["virustotal_results"].append(vt_result)
            if not was_cached and VIRUSTOTAL_API_KEY:
                time.sleep(VIRUSTOTAL_RATE_LIMIT_DELAY)

    # Step 4: Build risk summary
    url_count = len(scan["urls"])
    ip_count = len(scan["ips"])
    b64_count = len(scan["base64_strings"])
    hex_count = len(scan.get("hex_strings", []))
    firebase_count = len(scan.get("firebase_findings", []))
    s3_count = len(scan.get("s3_buckets", []))
    sens_count = len(scan.get("sensitive_strings", []))
    ast_count = len(scan.get("ast_findings", []))
    crypto_count = len(scan.get("crypto_wallets", []))
    secret_count = len(scan.get("high_entropy_secrets", []))
    malicious_ips = sum(
        1 for r in inspection["abuseipdb_results"]
        if r.get("abuse_confidence_score", 0) >= 25
    )
    malicious_urls = sum(
        1 for r in inspection["virustotal_results"]
        if r.get("malicious_votes", 0) > 0
    )

    parts = []
    if url_count:
        parts.append(f"{url_count} URL(s)")
    if ip_count:
        parts.append(f"{ip_count} IP(s)")
    if b64_count:
        parts.append(f"{b64_count} Base64 string(s)")
    if hex_count:
        parts.append(f"{hex_count} Hex string(s)")
    if firebase_count:
        parts.append(f"{firebase_count} Firebase indicator(s)")
    if s3_count:
        parts.append(f"{s3_count} S3 bucket(s)")
    if sens_count:
        parts.append(f"{sens_count} Sensitive string(s)")
    if ast_count:
        parts.append(f"{ast_count} AST finding(s)")
    if crypto_count:
        parts.append(f"{crypto_count} Crypto wallet(s)")
    if secret_count:
        parts.append(f"{secret_count} High-entropy secret(s)")
    if malicious_ips:
        parts.append(f"{malicious_ips} IP(s) flagged by AbuseIPDB")
    if malicious_urls:
        parts.append(f"{malicious_urls} URL(s) flagged by VirusTotal")

    inspection["risk_summary"] = " | ".join(parts)

    return inspection


# ═══════════════════════════════════════════════════════════════
# DISPLAY: RICH TERMINAL OUTPUT
# ═══════════════════════════════════════════════════════════════

def display_inspection_results(inspections: List[Dict], only_critical: bool = False) -> None:
    """
    Display the results of deep package inspections in a Rich terminal panel.

    Args:
        inspections: List of dicts returned by deep_inspect_package().
    """
    if not inspections:
        return

    # Filter to only inspections that found something
    active = [i for i in inspections if i.get("risk_summary") and i["risk_summary"] != "No IOCs found"]
    if not active:
        console.print(f"  [bold green][OK] No suspicious indicators found in scanned packages.[/]")
        return

    for inspection in active:
        pkg_name = inspection["package"]
        scan = inspection["scan_results"]
        abuse_results = inspection.get("abuseipdb_results", [])
        
        vt_lookup = {r["url"]: r for r in inspection.get("virustotal_results", [])}
        abuse_lookup = {r["ip"]: r for r in abuse_results}
        
        urls_to_show = scan.get("urls", [])
        ips_to_show = scan.get("ips", [])
        b64_to_show = scan.get("base64_strings", [])
        hex_to_show = scan.get("hex_strings", [])
        firebase_to_show = scan.get("firebase_findings", [])
        s3_to_show = scan.get("s3_buckets", [])
        sens_to_show = scan.get("sensitive_strings", [])
        ast_to_show = scan.get("ast_findings", [])
        crypto_to_show = scan.get("crypto_wallets", [])
        secrets_to_show = scan.get("high_entropy_secrets", [])
        
        if only_critical:
            if b64_to_show or ast_to_show or hex_to_show or firebase_to_show or s3_to_show or sens_to_show or crypto_to_show or secrets_to_show:
                # If the package has highly suspicious hidden payloads or AST behaviors, it is compromised.
                # Do NOT filter its URLs and IPs, show everything to the analyst!
                pass
            else:
                urls_to_show = [u for u in urls_to_show if vt_lookup.get(u["value"], {}).get("malicious_votes", 0) > 0]
                ips_to_show = [ip for ip in ips_to_show if abuse_lookup.get(ip["value"], {}).get("abuse_confidence_score", -1) >= 25]
            
        if not (urls_to_show or ips_to_show or b64_to_show or ast_to_show or hex_to_show or firebase_to_show or s3_to_show or sens_to_show or crypto_to_show or secrets_to_show):
            continue

        # ── URLs Table ──
        if urls_to_show:
            url_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            url_table.add_column("#", style="dim", width=4, justify="right")
            url_table.add_column("URL", style="bold yellow", min_width=50)
            url_table.add_column("File", style="dim cyan", min_width=25)
            url_table.add_column("Line", style="dim", width=6, justify="right")
            url_table.add_column("VirusTotal", justify="center", min_width=15)
            
            for idx, url_entry in enumerate(urls_to_show, 1):
                url = url_entry["value"]
                vt = vt_lookup.get(url, {})
                malicious = vt.get("malicious_votes", 0)
                total = vt.get("total_votes", 0)
                error = vt.get("error", "")
                
                if error:
                    vt_display = f"[dim yellow]{error}[/]"
                elif malicious > 0:
                    vt_display = f"[bold white on red] {malicious}/{total} MALICIOUS [/]"
                elif total > 0:
                    vt_display = f"[green]0/{total} Clean[/]"
                else:
                    vt_display = "[dim]N/A[/]"

                url_table.add_row(
                    str(idx),
                    escape(url),
                    escape(url_entry["file"]),
                    str(url_entry["line"]),
                    vt_display
                )

            console.print(Panel(
                url_table,
                title=f"[bold red] [!!] SUSPICIOUS URLs in '{pkg_name}' ({len(urls_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── IPs Table (with AbuseIPDB scores) ──
        if ips_to_show:
            ip_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            ip_table.add_column("#", style="dim", width=4, justify="right")
            ip_table.add_column("IP Address", style="bold yellow", min_width=18)
            ip_table.add_column("File", style="dim cyan", min_width=20)
            ip_table.add_column("Line", style="dim", width=6, justify="right")
            ip_table.add_column("AbuseIPDB Score", justify="center", min_width=16)
            ip_table.add_column("Reports", justify="center", min_width=8)
            ip_table.add_column("Country", justify="center", min_width=8)
            ip_table.add_column("ISP", min_width=20)

            for idx, ip_entry in enumerate(ips_to_show, 1):
                ip = ip_entry["value"]
                abuse = abuse_lookup.get(ip, {})
                score = abuse.get("abuse_confidence_score", -1)
                reports = abuse.get("total_reports", 0)
                country = abuse.get("country_code")
                country = country if country is not None else "??"
                isp = abuse.get("isp")
                isp = isp if isp is not None else "Unknown"
                error = abuse.get("error", "")

                if error:
                    score_display = f"[dim yellow]{error}[/]"
                elif score >= 75:
                    score_display = f"[bold white on red] {score}% MALICIOUS [/]"
                elif score >= 25:
                    score_display = f"[bold yellow]{score}% Suspicious[/]"
                elif score >= 0:
                    score_display = f"[green]{score}% Clean[/]"
                else:
                    score_display = "[dim]N/A[/]"

                ip_table.add_row(
                    str(idx), escape(ip), escape(ip_entry["file"]), str(ip_entry["line"]),
                    score_display, str(reports), escape(country), escape(isp),
                )

            console.print(Panel(
                ip_table,
                title=f"[bold red] [!!] SUSPICIOUS IPs in '{pkg_name}' ({len(ips_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── Base64 Table ──
        if b64_to_show:
            b64_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            b64_table.add_column("#", style="dim", width=4, justify="right")
            b64_table.add_column("Encoded String", style="bold yellow", min_width=40)
            b64_table.add_column("Decoded Preview", style="dim magenta", min_width=30)
            b64_table.add_column("File", style="dim cyan", min_width=20)
            b64_table.add_column("Line", style="dim", width=6, justify="right")
            b64_table.add_column("Flags", style="bold red", min_width=15)

            for idx, b64_entry in enumerate(b64_to_show, 1):
                flags = []
                if b64_entry.get("contains_cred"):
                    flags.append("CREDENTIAL")
                if b64_entry.get("contains_url"):
                    flags.append("URL")
                flags_str = " | ".join(flags)

                b64_table.add_row(
                    str(idx),
                    escape(b64_entry["value"]),
                    escape(b64_entry["decoded_preview"]),
                    escape(b64_entry["file"]),
                    str(b64_entry["line"]),
                    flags_str
                )

            console.print(Panel(
                b64_table,
                title=f"[bold red] [!!] SUSPICIOUS Base64 in '{pkg_name}' ({len(b64_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── Hex Strings Table ──
        if hex_to_show:
            hex_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            hex_table.add_column("#", style="dim", width=4, justify="right")
            hex_table.add_column("Hex String / Escape", style="bold yellow", min_width=40)
            hex_table.add_column("File", style="dim cyan", min_width=20)
            hex_table.add_column("Line", style="dim", width=6, justify="right")

            for idx, hex_entry in enumerate(hex_to_show, 1):
                hex_table.add_row(
                    str(idx),
                    escape(hex_entry["value"]),
                    escape(hex_entry["file"]),
                    str(hex_entry["line"])
                )

            console.print(Panel(
                hex_table,
                title=f"[bold red] [!!] SUSPICIOUS HEX STRINGS in '{pkg_name}' ({len(hex_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── Firebase Findings Table ──
        if firebase_to_show:
            fb_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            fb_table.add_column("#", style="dim", width=4, justify="right")
            fb_table.add_column("Type", style="bold magenta", min_width=15)
            fb_table.add_column("Indicator Value", style="bold yellow", min_width=35)
            fb_table.add_column("File", style="dim cyan", min_width=20)
            fb_table.add_column("Line", style="dim", width=6, justify="right")

            for idx, fb_entry in enumerate(firebase_to_show, 1):
                fb_table.add_row(
                    str(idx),
                    escape(fb_entry["type"]),
                    escape(fb_entry["value"]),
                    escape(fb_entry["file"]),
                    str(fb_entry["line"])
                )

            console.print(Panel(
                fb_table,
                title=f"[bold red] [!!] FIREBASE FINDINGS in '{pkg_name}' ({len(firebase_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── S3 Buckets Table ──
        if s3_to_show:
            s3_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            s3_table.add_column("#", style="dim", width=4, justify="right")
            s3_table.add_column("S3 Bucket / URL", style="bold yellow", min_width=40)
            s3_table.add_column("File", style="dim cyan", min_width=20)
            s3_table.add_column("Line", style="dim", width=6, justify="right")

            for idx, s3_entry in enumerate(s3_to_show, 1):
                s3_table.add_row(
                    str(idx),
                    escape(s3_entry["value"]),
                    escape(s3_entry["file"]),
                    str(s3_entry["line"])
                )

            console.print(Panel(
                s3_table,
                title=f"[bold red] [!!] S3 BUCKETS in '{pkg_name}' ({len(s3_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── Sensitive Strings / Cloud Assets Table ──
        if sens_to_show:
            sens_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            sens_table.add_column("#", style="dim", width=4, justify="right")
            sens_table.add_column("Type", style="bold magenta", min_width=15)
            sens_table.add_column("Asset / Webhook", style="bold yellow", min_width=35)
            sens_table.add_column("File", style="dim cyan", min_width=20)
            sens_table.add_column("Line", style="dim", width=6, justify="right")

            for idx, sens_entry in enumerate(sens_to_show, 1):
                sens_table.add_row(
                    str(idx),
                    escape(sens_entry["type"]),
                    escape(sens_entry["value"]),
                    escape(sens_entry["file"]),
                    str(sens_entry["line"])
                )

            console.print(Panel(
                sens_table,
                title=f"[bold red] [!!] CLOUD ASSETS & WEBHOOKS in '{pkg_name}' ({len(sens_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── AST Findings Table ──
        if ast_to_show:
            ast_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            ast_table.add_column("#", style="dim", width=4, justify="right")
            ast_table.add_column("Finding Type", style="bold yellow", min_width=25)
            ast_table.add_column("Description", style="white", min_width=45)
            ast_table.add_column("File", style="dim cyan", min_width=20)
            ast_table.add_column("Line", style="dim", width=6, justify="right")

            for idx, ast_entry in enumerate(ast_to_show, 1):
                ast_table.add_row(
                    str(idx),
                    escape(ast_entry["type"]),
                    escape(ast_entry["description"]),
                    escape(ast_entry["file"]),
                    str(ast_entry["line"])
                )

            console.print(Panel(
                ast_table,
                title=f"[bold red] [!!] BEHAVIORAL AST FINDINGS in '{pkg_name}' ({len(ast_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── Crypto Wallets Table ──
        if crypto_to_show:
            crypto_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            crypto_table.add_column("#", style="dim", width=4, justify="right")
            crypto_table.add_column("Address", style="bold yellow", min_width=40)
            crypto_table.add_column("Type", style="bold magenta", min_width=18)
            crypto_table.add_column("File", style="dim cyan", min_width=20)
            crypto_table.add_column("Line", style="dim", width=6, justify="right")

            for idx, cw_entry in enumerate(crypto_to_show, 1):
                addr = cw_entry["value"]
                truncated_addr = addr[:40] + "..." if len(addr) > 40 else addr
                crypto_table.add_row(
                    str(idx),
                    escape(truncated_addr),
                    escape(cw_entry["type"]),
                    escape(cw_entry["file"]),
                    str(cw_entry["line"]),
                )

            console.print(Panel(
                crypto_table,
                title=f"[bold red] [!!] CRYPTO WALLET ADDRESSES in '{pkg_name}' ({len(crypto_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── High-Entropy Secrets Table ──
        if secrets_to_show:
            secrets_table = Table(
                show_header=True,
                header_style="bold white on dark_red",
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            secrets_table.add_column("#", style="dim", width=4, justify="right")
            secrets_table.add_column("Secret", style="bold yellow", min_width=40)
            secrets_table.add_column("Context", style="bold magenta", min_width=18)
            secrets_table.add_column("Entropy", style="white", width=8, justify="right")
            secrets_table.add_column("File", style="dim cyan", min_width=20)
            secrets_table.add_column("Line", style="dim", width=6, justify="right")

            for idx, sec_entry in enumerate(secrets_to_show, 1):
                # Mask the middle of the secret for display
                raw_val = sec_entry["value"]
                if len(raw_val) > 12:
                    masked_val = raw_val[:6] + "*" * min(len(raw_val) - 10, 20) + raw_val[-4:]
                else:
                    masked_val = raw_val
                secrets_table.add_row(
                    str(idx),
                    escape(masked_val),
                    escape(sec_entry["context"]),
                    str(sec_entry["entropy"]),
                    escape(sec_entry["file"]),
                    str(sec_entry["line"]),
                )

            console.print(Panel(
                secrets_table,
                title=f"[bold red] [!!] HIGH-ENTROPY SECRETS in '{pkg_name}' ({len(secrets_to_show)} found) [/]",
                border_style="red",
                padding=(0, 1),
            ))

        # ── Summary Line ──
        console.print(
            f"  [bold red][!!] Deep Scan Summary for '{pkg_name}':[/] "
            f"[yellow]{inspection['risk_summary']}[/]"
        )


def get_package_install_path(package_name: str, ecosystem: str, container_name: str = None) -> str:
    """
    Attempt to locate the installed package directory on the local filesystem or inside a container.

    Args:
        package_name: Name of the package.
        ecosystem: Ecosystem identifier.
        container_name: If provided, attempts to docker cp the package from this container to a temp dir.

    Returns:
        Absolute path to the package directory, or empty string if not found.
    """
    if container_name:
        if ecosystem == "PyPI":
            pkg_module = package_name.replace("-", "_")
            cmd = [
                "docker", "exec", container_name,
                "python", "-c",
                f"import importlib.util, os; spec=importlib.util.find_spec('{pkg_module}'); "
                f"print(os.path.dirname(spec.origin) if spec and spec.origin else '')"
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                remote_path = result.stdout.strip()
                if remote_path and "error" not in remote_path.lower():
                    # docker cp to a temp folder
                    tmp_dir = tempfile.mkdtemp(prefix=f"scs_{package_name}_")
                    local_dest = os.path.join(tmp_dir, package_name)
                    cp_cmd = ["docker", "cp", "-L", f"{container_name}:{remote_path}", local_dest]
                    subprocess.run(cp_cmd, capture_output=True, timeout=15)
                    if os.path.isdir(local_dest):
                        return local_dest
            except Exception:
                pass
        
        elif ecosystem == "npm":
            try:
                # Try common standard locations for npm packages in docker containers (like /app/node_modules)
                remote_path = f"/app/node_modules/{package_name}"
                
                # Resolve the real path in the container (in case it's a symlink, e.g. local 'file:' packages)
                resolve_cmd = ["docker", "exec", container_name, "readlink", "-f", remote_path]
                res = subprocess.run(resolve_cmd, capture_output=True, text=True, timeout=10)
                real_remote_path = res.stdout.strip()
                if real_remote_path and "error" not in real_remote_path.lower():
                    remote_path = real_remote_path
                    
                tmp_dir = tempfile.mkdtemp(prefix=f"scs_{package_name}_")
                local_dest = os.path.join(tmp_dir, package_name)
                cp_cmd = ["docker", "cp", f"{container_name}:{remote_path}", local_dest]
                subprocess.run(cp_cmd, capture_output=True, timeout=15)
                if os.path.isdir(local_dest):
                    return local_dest
            except Exception:
                pass

        return ""

    # Existing local filesystem check
    if ecosystem == "PyPI":
        # Try importlib.metadata to find the package location
        try:
            import importlib.metadata as metadata
            dist = metadata.distribution(package_name)
            # The _path attribute or files[0] can give us the location
            if dist._path:
                pkg_dir = str(dist._path)
                if os.path.isdir(pkg_dir):
                    return pkg_dir
        except Exception:
            pass

        # Fallback: search in site-packages
        import site
        for sp in site.getsitepackages() + [site.getusersitepackages()]:
            candidate = os.path.join(sp, package_name.replace("-", "_"))
            if os.path.isdir(candidate):
                return candidate
            # Also check with the original name
            candidate2 = os.path.join(sp, package_name)
            if os.path.isdir(candidate2):
                return candidate2

    elif ecosystem == "npm":
        # Check common node_modules locations
        cwd = os.getcwd()
        candidate = os.path.join(cwd, "node_modules", package_name)
        if os.path.isdir(candidate):
            return candidate

    return ""
