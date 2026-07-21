"""
Supply Chain Sentinel — Configuration
======================================
Shared constants and configuration values used across all monitoring modules.
"""

import os
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# DOCKER
# ═══════════════════════════════════════════════════════════════
DEFAULT_IMAGE_NAME = "vulnapp:latest"
DEFAULT_DOCKERFILE_PATH = "../app"

# ═══════════════════════════════════════════════════════════════
# SBOM
# ═══════════════════════════════════════════════════════════════
SBOM_OUTPUT_FORMAT = "cyclonedx-json"
SBOM_OUTPUT_FILE = "sbom.json"

# ═══════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════
PYPI_API_BASE = "https://pypi.org/pypi"
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_API_URL = "https://api.osv.dev/v1/querybatch"

# GitHub Advisory Database (public, no token required for read)
GITHUB_ADVISORY_API_URL = "https://api.github.com/advisories"

# npm Audit Advisory API
NPM_AUDIT_API_URL = "https://registry.npmjs.org/-/npm/v1/security/advisories"

# AbuseIPDB — IP reputation checking
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_RATE_LIMIT_DELAY = 0.3   # 300ms between AbuseIPDB requests

# VirusTotal — URL reputation checking
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_RATE_LIMIT_DELAY = 15.0  # VT Public API allows 4 requests/min

# Google Gemini — AI-powered code intelligence
# Pass your API key via the GEMINI_API_KEY environment variable.
# To use key rotation/failover, pass multiple keys separated by commas in GEMINI_API_KEY.
_raw_gemini_keys = os.environ.get("GEMINI_API_KEY", "")
GEMINI_API_KEYS = [k.strip() for k in _raw_gemini_keys.split(",") if k.strip() and k.strip() != "YOUR_GEMINI_API_KEY_HERE"]
GEMINI_API_KEY = GEMINI_API_KEYS[0] if GEMINI_API_KEYS else ""
SENTINEL_AI_MODEL = os.environ.get("SENTINEL_AI_MODEL", "gemini-3.5-flash")

# ═══════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════
REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
REPORT_FILENAME_TEMPLATE = "supply_chain_audit_{timestamp}.xlsx"
RUNTIME_LOG_FILE = os.path.join(REPORT_DIR, "runtime_alerts.log")

# ═══════════════════════════════════════════════════════════════
# RATE LIMITING
# ═══════════════════════════════════════════════════════════════
PYPI_RATE_LIMIT_DELAY = 0.1       # 100ms between PyPI requests
OSV_RATE_LIMIT_DELAY = 0.1        # 100ms between OSV requests
GITHUB_RATE_LIMIT_DELAY = 0.2     # 200ms between GitHub API requests
NPM_RATE_LIMIT_DELAY = 0.1        # 100ms between npm API requests
REGISTRY_RATE_LIMIT_DELAY = 0.1   # 100ms between registry lookups
REQUEST_TIMEOUT = 15               # Seconds

# ═══════════════════════════════════════════════════════════════
# SEVERITY THRESHOLDS (CVSS v3)
# ═══════════════════════════════════════════════════════════════
SEVERITY_THRESHOLDS = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 0.1,
    "NONE": 0.0,
}

# ═══════════════════════════════════════════════════════════════
# VISUAL STYLES — Severity Color Palette
# ═══════════════════════════════════════════════════════════════
SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold blue",
    "NONE":     "bold green",
}

SEVERITY_ICONS = {
    "CRITICAL": "[!!!]",
    "HIGH":     "[!!]",
    "MEDIUM":   "[!]",
    "LOW":      "[~]",
    "NONE":     "[OK]",
}

# ═══════════════════════════════════════════════════════════════
# CONSOLE BRANDING
# ═══════════════════════════════════════════════════════════════
BANNER = r"""
[bold cyan]
  +====================================================================+
  |                                                                    |
  |               ___  ___ _ __ | |_(_)_ __   ___| |                   |
  |              / __|/ _ \ '_ \| __| | '_ \ / _ \ |                   |
  |              \__ \  __/ | | | |_| | | | |  __/ |                   |
  |              |___/\___|_| |_|\__|_|_| |_|\___|_|                   |
  |                                                                    |
  |         SUPPLY CHAIN SENTINEL  (Multi-Ecosystem + AI)              |
  |         SBOM Generation & Dependency Auditing                      |
  |         Python | Node.js | Go | Ruby | Java | Rust | PHP | .NET    |
  |         Threat Intel: OSV + GitHub Advisory + npm Audit            |
  |         AI Engine: Intent | De-Obfuscation | Zero-Day | SOC       |
  |                                                                    |
  +====================================================================+
[/bold cyan]
"""

# ═══════════════════════════════════════════════════════════════
# ZERO-TRUST NETWORK ALLOWLISTS
# ═══════════════════════════════════════════════════════════════
# Connections to domains/IPs NOT on these lists will be flagged.
# Wildcards supported: "*.npmjs.org" matches "registry.npmjs.org".
# Set to None to disable allowlist mode (only reputation checks).

ALLOWED_DOMAINS = [
    # Package registries
    "*.npmjs.org",
    "*.pypi.org",
    "*.rubygems.org",
    "*.crates.io",
    "*.packagist.org",
    "*.nuget.org",
    "*.golang.org",
    "*.proxy.golang.org",
    "*.pkg.go.dev",
    "*.maven.org",
    # Common CDNs & infrastructure
    "*.cloudflare.com",
    "*.fastly.net",
    "*.akamaiedge.net",
    "*.amazonaws.com",
    "*.googleapis.com",
    "*.github.com",
    "*.github.io",
    "*.githubusercontent.com",
    # DNS
    "*.dns.google",
    "*.cloudflare-dns.com",
]

ALLOWED_IPS = [
    # Google DNS
    "8.8.8.8",
    "8.8.4.4",
    # Cloudflare DNS
    "1.1.1.1",
    "1.0.0.1",
]

# ═══════════════════════════════════════════════════════════════
# DOMAIN AGE — RDAP WHOIS
# ═══════════════════════════════════════════════════════════════
RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/"
SUSPICIOUS_DOMAIN_AGE_DAYS = 30       # Flag domains registered < 30 days ago
RDAP_TIMEOUT = 8                      # Seconds per RDAP query
RDAP_RATE_LIMIT_DELAY = 0.5           # 500ms between RDAP queries
WHOIS_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".whois_cache.json",
)

# ═══════════════════════════════════════════════════════════════
# DNS TUNNELING DETECTION
# ═══════════════════════════════════════════════════════════════
DNS_BURST_THRESHOLD = 20              # Max DNS queries from one package in 10s
DNS_BURST_WINDOW_SECONDS = 10         # Time window for burst detection
DNS_SUBDOMAIN_LEN_LIMIT = 40          # Flag subdomains longer than this
DNS_ENTROPY_THRESHOLD = 3.5           # Shannon entropy threshold for subdomain

# ═══════════════════════════════════════════════════════════════
# RAW IP DETECTION
# ═══════════════════════════════════════════════════════════════
RAW_IP_ALLOW_STANDARD_PORTS = False   # If True, raw IPs on 80/443 are not flagged


def step_header(step_num, title: str, icon: str = ">") -> str:
    """Generate a styled step header for pipeline progress."""
    return (
        f"\n[bold bright_cyan]"
        f"  {'='*60}\n"
        f"   STEP {step_num}  {icon}  {title}\n"
        f"  {'='*60}"
        f"[/bold bright_cyan]"
    )
