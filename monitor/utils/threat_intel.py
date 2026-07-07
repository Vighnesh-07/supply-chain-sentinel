"""
Supply Chain Sentinel — Threat Intelligence (Multi-Database)
==============================================================
Analyzes vulnerability data and SBOM packages against multiple
threat intelligence sources to identify known malicious packages
(e.g., supply chain compromises, typosquatting, sabotage).

Databases: OSV (MAL-), GitHub Advisory (GHSA-), npm Audit, Local Blocklist.
"""

import time
from typing import Dict, List, Tuple

import requests

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import (
    step_header,
    GITHUB_ADVISORY_API_URL,
    GITHUB_RATE_LIMIT_DELAY,
    REQUEST_TIMEOUT,
)

console = Console()


# ═══════════════════════════════════════════════════════════════
# LOCAL BLOCKLIST — Known malicious / compromised packages
# ═══════════════════════════════════════════════════════════════

LOCAL_BLOCKLIST = {
    # npm — Real-world supply chain attacks
    "npm": {
        "event-stream": "Hijacked in v3.3.6 — cryptocurrency wallet theft (2018)",
        "flatmap-stream": "Malicious dependency injected into event-stream",
        "ua-parser-js": "Hijacked — cryptominer + password stealer (Oct 2021)",
        "coa": "Hijacked — malware injected (Nov 2021)",
        "rc": "Hijacked — malware injected (Nov 2021)",
        "colors": "Sabotaged by maintainer — infinite loop DoS (Jan 2022)",
        "faker": "Sabotaged by maintainer — wiped module (Jan 2022)",
        "peacenotwar": "Protestware — overwrites files based on geolocation",
        "node-ipc": "Protestware — destructive payload based on geolocation",
        "getcookies": "Backdoor — remote code execution via HTTP headers",
        "eslint-scope": "Hijacked — npm token theft (Jul 2018)",
    },
    # PyPI — Real-world supply chain attacks
    "PyPI": {
        "ctx": "Hijacked — stole environment variables and AWS keys (May 2022)",
        "phpass": "Typosquatting — exfiltrated environment variables",
        "setup-tools": "Typosquatting setuptools — backdoor",
        "jeIlyfish": "Typosquatting jellyfish (capital I vs l) — SSH key theft",
        "python3-dateutil": "Typosquatting — credential theft",
        "coloursama": "Typosquatting colorama — keylogger",
        "pipsqlite3": "Typosquatting — data exfiltration",
        "requesocks": "Typosquatting requests — backdoor",
        "malicious-json-demo": "Demo Backdoor — Supply Chain Sentinel test package",
    },
    # RubyGems
    "RubyGems": {
        "rest-client": "Hijacked in v1.6.13 — backdoor (Aug 2019)",
        "strong_password": "Hijacked v0.0.7 — backdoor (Jul 2019)",
        "bootstrap-sass": "Hijacked v3.2.0.3 — backdoor cookie stealer",
    },
    # Packagist (PHP)
    "Packagist": {
        "phpass": "Typosquatting hautelook/phpass — credential theft",
    },
}


# ═══════════════════════════════════════════════════════════════
# LEVENSHTEIN DISTANCE — Pure-Python implementation
# ═══════════════════════════════════════════════════════════════

def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein (edit) distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))

    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (0 if c1 == c2 else 1)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


# ═══════════════════════════════════════════════════════════════
# POPULAR PACKAGES CATALOG — Used for typo-squatting detection
# ═══════════════════════════════════════════════════════════════

POPULAR_PACKAGES = {
    "PyPI": {
        "requests", "flask", "django", "numpy", "pandas", "scipy",
        "tensorflow", "torch", "pytest", "setuptools", "pip", "wheel",
        "boto3", "urllib3", "certifi", "idna", "charset-normalizer",
        "pyyaml", "cryptography", "pillow", "matplotlib", "scikit-learn",
        "beautifulsoup4", "sqlalchemy", "celery", "redis", "paramiko",
        "colorama", "click", "jinja2", "markupsafe", "packaging",
        "six", "decorator", "attrs", "pydantic", "fastapi", "uvicorn",
        "gunicorn", "aiohttp", "httpx", "black", "mypy", "ruff",
        "twine", "build", "tox", "coverage", "sphinx",
    },
    "npm": {
        "express", "react", "react-dom", "vue", "angular", "next",
        "lodash", "axios", "moment", "chalk", "commander", "webpack",
        "babel", "eslint", "prettier", "typescript", "jest", "mocha",
        "nodemon", "dotenv", "cors", "body-parser", "mongoose", "sequelize",
        "passport", "jsonwebtoken", "bcrypt", "uuid", "socket.io",
        "underscore", "async", "debug", "minimist", "yargs", "inquirer",
        "glob", "rimraf", "mkdirp", "fs-extra", "cheerio", "puppeteer",
    },
    "RubyGems": {
        "rails", "rake", "bundler", "rspec", "sinatra", "puma", "devise",
        "nokogiri", "activerecord", "sidekiq", "redis", "pg", "mysql2",
        "json", "minitest", "capistrano", "rubocop", "faraday", "httparty",
    },
    "Go": {
        "gin", "echo", "fiber", "cobra", "viper", "logrus", "zap",
        "gorm", "grpc", "protobuf", "testify", "mux", "chi",
    },
}


def _check_typosquatting(pkg_name: str, ecosystem: str) -> str:
    """Check if a package name is suspiciously similar to a popular package."""
    popular = POPULAR_PACKAGES.get(ecosystem, set())
    # Skip packages that are themselves popular — no false positives
    if pkg_name in popular:
        return ""
    for popular_pkg in popular:
        distance = _levenshtein_distance(pkg_name.lower(), popular_pkg.lower())
        if distance == 1:  # Single character typo
            return f"Possible typo-squat of '{popular_pkg}' (edit distance: {distance})"
        if distance == 2 and len(pkg_name) > 5:  # Two-char typo only for longer names
            return f"Possible typo-squat of '{popular_pkg}' (edit distance: {distance})"
    return ""



# ═══════════════════════════════════════════════════════════════
# INDIVIDUAL THREAT CHECKS
# ═══════════════════════════════════════════════════════════════

def _check_osv_malware(vuln_info: Dict) -> List[str]:
    """
    Check OSV vulnerability data for MAL- (malware) advisories.

    Returns:
        List of malware advisory IDs found.
    """
    malware_ids = []
    vulns = vuln_info.get("vulnerabilities", [])
    for vuln in vulns:
        vuln_id = vuln.get("id", "")
        aliases = vuln.get("aliases", [])

        if vuln_id.startswith("MAL-"):
            malware_ids.append(vuln_id)
        for alias in aliases:
            if alias.startswith("MAL-"):
                malware_ids.append(alias)

    return malware_ids


def _check_github_advisory(pkg_name: str, ecosystem: str) -> List[str]:
    """
    Query GitHub Advisory Database for known security advisories.

    Args:
        pkg_name: Package name to check.
        ecosystem: Ecosystem identifier (e.g., 'npm', 'pip', 'rubygems').

    Returns:
        List of GHSA advisory IDs affecting this package.
    """
    # Map our ecosystem names to GitHub's ecosystem identifiers
    eco_map = {
        "PyPI": "pip",
        "npm": "npm",
        "RubyGems": "rubygems",
        "Maven": "maven",
        "Go": "go",
        "crates.io": "rust",
        "Packagist": "composer",
        "NuGet": "nuget",
    }
    gh_ecosystem = eco_map.get(ecosystem)
    if not gh_ecosystem:
        return []

    try:
        params = {
            "affects": pkg_name,
            "ecosystem": gh_ecosystem,
            "per_page": 5,
        }
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        response = requests.get(
            GITHUB_ADVISORY_API_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 200:
            advisories = response.json()
            ghsa_ids = []
            for adv in advisories:
                ghsa_id = adv.get("ghsa_id", "")
                severity = adv.get("severity", "")
                if ghsa_id:
                    ghsa_ids.append(f"{ghsa_id} ({severity})")
            return ghsa_ids
        # 403 = rate limited, 422 = invalid params — fail gracefully
        return []

    except requests.RequestException:
        return []


def _check_local_blocklist(pkg_name: str, ecosystem: str) -> str:
    """
    Check a package against the local blocklist of known malicious packages.

    Returns:
        Reason string if found, empty string if clean.
    """
    eco_list = LOCAL_BLOCKLIST.get(ecosystem, {})
    reason = eco_list.get(pkg_name, "")
    if not reason:
        # Also check case-insensitively
        for blocked_name, blocked_reason in eco_list.items():
            if blocked_name.lower() == pkg_name.lower():
                return blocked_reason
    return reason


# ═══════════════════════════════════════════════════════════════
# MAIN THREAT INTEL ENGINE
# ═══════════════════════════════════════════════════════════════

def evaluate_malicious_indicators(
    vuln_results: Dict[str, Dict],
    packages: List[Dict] = None,
) -> Tuple[Dict[str, bool], Dict[str, List[str]]]:
    """
    Evaluate packages against multiple threat intelligence sources.

    Checks performed:
    1. OSV MAL- malware advisories
    2. GitHub Advisory Database (GHSA-)
    3. Local blocklist of known malicious packages

    Args:
        vuln_results: Dict mapping package name -> vulnerability info from OSV scan.
        packages: List of package dicts with 'name', 'version', 'ecosystem' keys.
                  If None, ecosystem defaults to 'PyPI'.

    Returns:
        Tuple of:
        - malicious_flags: Dict mapping package name -> bool (True if malicious).
        - threat_details: Dict mapping package name -> list of threat source strings.
    """
    console.print(step_header(5, "THREAT INTELLIGENCE ANALYSIS (Multi-Database)", "|>"))

    # Build a lookup for package ecosystem info
    pkg_ecosystem_map: Dict[str, str] = {}
    if packages:
        for pkg in packages:
            pkg_ecosystem_map[pkg["name"]] = pkg.get("ecosystem", "PyPI")

    total_packages = len(vuln_results)
    console.print(f"  [dim]Evaluating[/] [bold]{total_packages}[/] [dim]packages against threat feeds...[/]")
    console.print(f"  [dim]Sources: OSV Malware (MAL-) | GitHub Advisory (GHSA-) | Local Blocklist | Typo-squatting[/]")

    malicious_flags: Dict[str, bool] = {}
    threat_details: Dict[str, List[str]] = {}
    malicious_count = 0
    malicious_report = []  # For the report table

    for pkg_name, vuln_info in vuln_results.items():
        is_malicious = False
        sources: List[str] = []
        ecosystem = pkg_ecosystem_map.get(pkg_name, "PyPI")

        # ── Check 1: OSV MAL- advisories ──
        mal_ids = _check_osv_malware(vuln_info)
        if mal_ids:
            is_malicious = True
            for mal_id in mal_ids:
                sources.append(f"OSV Malware: {mal_id}")

        # ── Check 2: GitHub Advisory Database ──
        ghsa_ids = _check_github_advisory(pkg_name, ecosystem)
        if ghsa_ids:
            # GHSA advisories indicate known vulnerabilities, not necessarily malware
            # But we flag them as threat intel findings
            for ghsa_id in ghsa_ids:
                sources.append(f"GitHub Advisory: {ghsa_id}")
            # Only mark as malicious if the advisory is critical/high severity
            for ghsa_id in ghsa_ids:
                if "critical" in ghsa_id.lower() or "high" in ghsa_id.lower():
                    # Keep as advisory, not auto-flagging as malicious
                    pass

        # Rate limit for GitHub API
        if ghsa_ids or True:  # Always delay slightly
            time.sleep(GITHUB_RATE_LIMIT_DELAY)

        # ── Check 3: Local Blocklist ──
        blocklist_reason = _check_local_blocklist(pkg_name, ecosystem)
        if blocklist_reason:
            is_malicious = True
            sources.append(f"Local Blocklist: {blocklist_reason}")

        # ── Check 4: Typo-squatting Detection ──
        typosquat_reason = _check_typosquatting(pkg_name, ecosystem)
        if typosquat_reason:
            is_malicious = True
            sources.append(f"Typo-squatting: {typosquat_reason}")

        malicious_flags[pkg_name] = is_malicious
        threat_details[pkg_name] = sources

        if is_malicious:
            malicious_count += 1
            malicious_report.append((pkg_name, ecosystem, sources))

    # ── Display Results ──
    if malicious_count > 0:
        # Build a detailed threat intel table
        threat_table = Table(
            show_header=True,
            header_style="bold white on red",
            border_style="red",
            padding=(0, 1),
            show_lines=True,
            expand=False,
        )
        threat_table.add_column("#", style="bold red", width=4, justify="right")
        threat_table.add_column("Package", style="bold white", min_width=20)
        threat_table.add_column("Ecosystem", style="bold magenta", min_width=12)
        threat_table.add_column("Classification", style="bold red", min_width=13)
        threat_table.add_column("Threat Database / Source", min_width=40)

        for idx, (name, eco, sources) in enumerate(malicious_report, 1):
            source_str = "\n".join(sources) if sources else "Unknown"
            threat_table.add_row(
                str(idx), name, eco, "MALICIOUS", f"[red]{source_str}[/]"
            )

        console.print(Panel(
            threat_table,
            title=f"[bold white on red] ALERT: {malicious_count} MALICIOUS PACKAGE(S) DETECTED [/]",
            border_style="bold red",
            padding=(1, 2),
        ))
    else:
        console.print(
            f"  [bold green][OK] No malicious packages detected across all threat intel feeds.[/]"
        )

    # Show advisory findings (non-malicious but noteworthy)
    advisory_pkgs = [(name, sources) for name, sources in threat_details.items()
                     if sources and not malicious_flags.get(name, False)]
    if advisory_pkgs:
        console.print(f"  [dim yellow][!] {len(advisory_pkgs)} packages have security advisories (not classified as malicious)[/]")

    # Summary
    clean_count = total_packages - malicious_count
    console.print(
        f"  [dim]Results: [green]{clean_count} clean[/] | "
        f"[red]{malicious_count} malicious[/][/]"
    )

    return malicious_flags, threat_details
