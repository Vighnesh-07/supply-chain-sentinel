"""
Supply Chain Sentinel — Vulnerability Scanner (Multi-Ecosystem)
================================================================
Queries the OSV (Open Source Vulnerabilities) API to identify known
vulnerabilities for each package+version pair across all supported
ecosystems.

The OSV database aggregates vulnerability data from NVD, GitHub
Security Advisories, PyPI advisories, npm advisories, RubyGems,
Go, Maven, crates.io, and other sources.
"""

import time
from typing import List, Dict, Tuple

import requests

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .config import OSV_API_URL, OSV_RATE_LIMIT_DELAY, REQUEST_TIMEOUT, step_header, SEVERITY_STYLES, SEVERITY_ICONS
from .ecosystem_registry import get_osv_ecosystem

console = Console()


def _classify_severity(score: float) -> str:
    """
    Map a CVSS score to a human-readable severity label.

    Args:
        score: CVSS v3 score (0.0-10.0).

    Returns:
        Severity label: CRITICAL, HIGH, MEDIUM, LOW, or NONE.
    """
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "NONE"


import math

def _parse_cvss_vector(vector: str) -> float:
    """
    Approximates CVSS v3/3.1 base score from a vector string.
    e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    if not vector.startswith("CVSS:3"):
        return 0.0
        
    metrics = dict(part.split(":") for part in vector.split("/") if ":" in part)
    
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_c = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_weights = {"N": 0.85, "R": 0.62}
    cia_weights = {"H": 0.56, "L": 0.22, "N": 0.0}
    
    try:
        s = metrics.get("S", "U")
        av = av_weights.get(metrics.get("AV", "N"), 0.85)
        ac = ac_weights.get(metrics.get("AC", "L"), 0.77)
        ui = ui_weights.get(metrics.get("UI", "N"), 0.85)
        
        pr_w = pr_weights_c if s == "C" else pr_weights_u
        pr = pr_w.get(metrics.get("PR", "N"), 0.85)
        
        c = cia_weights.get(metrics.get("C", "N"), 0.0)
        i = cia_weights.get(metrics.get("I", "N"), 0.0)
        a = cia_weights.get(metrics.get("A", "N"), 0.0)
        
        iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        
        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss * 0.02) ** 15)
            
        exploitability = 8.22 * av * ac * pr * ui
        
        if impact <= 0:
            return 0.0
            
        if s == "U":
            score = impact + exploitability
        else:
            score = 1.08 * (impact + exploitability)
            
        return min(math.ceil(score * 10) / 10.0, 10.0)
    except Exception:
        return 0.0


def _extract_severity_info(vulns: List[Dict]) -> Tuple[str, float, List[str]]:
    """
    Extract the maximum severity and CVE IDs from a list of OSV vulnerabilities.

    Args:
        vulns: List of vulnerability objects from OSV API response.

    Returns:
        Tuple of (severity_label, max_cvss_score, list_of_cve_ids_with_scores).
    """
    max_score = 0.0
    cve_scores = {}

    for vuln in vulns:
        vuln_score = 0.0

        # 1. Parse CVSS vector strictly from OSV source data
        severity_list = vuln.get("severity", [])
        for sev in severity_list:
            sev_type = sev.get("type", "")
            score_val = sev.get("score", "")
            if sev_type.startswith("CVSS_V3") and isinstance(score_val, str):
                vuln_score = max(vuln_score, _parse_cvss_vector(score_val))

        # 2. Fallback to specific severity string if no vector is provided by OSV
        if vuln_score == 0.0:
            for spec in [vuln.get("database_specific", {}), vuln.get("ecosystem_specific", {})]:
                sev_str = spec.get("severity", "").upper()
                if sev_str:
                    mapping = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}
                    vuln_score = max(vuln_score, mapping.get(sev_str, 0.0))

        max_score = max(max_score, vuln_score)

        # 4. Associate this score with its CVE IDs (and OSV IDs if no CVE)
        aliases = vuln.get("aliases", [])
        vuln_id = vuln.get("id", "")

        cves = [a for a in aliases if a.startswith("CVE-")]
        if vuln_id.startswith("CVE-") and vuln_id not in cves:
            cves.append(vuln_id)

        # Fallback to primary ID if no CVEs
        if not cves and vuln_id:
            cves.append(vuln_id)

        for cve in cves:
            if cve not in cve_scores or cve_scores[cve] < vuln_score:
                cve_scores[cve] = vuln_score

    # Build the formatted list (CVEs first, then others)
    cve_ids_with_scores = []
    sorted_ids = sorted(cve_scores.keys(), key=lambda x: (not x.startswith("CVE-"), x))

    for cid in sorted_ids:
        score = cve_scores[cid]
        if score > 0.0:
            sev_label = _classify_severity(score)
            cve_ids_with_scores.append(f"{cid} ({score:.1f} {sev_label})")
        else:
            cve_ids_with_scores.append(f"{cid} (N/A)")

    severity_label = _classify_severity(max_score)
    if not vulns:
        severity_label = "NONE"
        max_score = 0.0
    elif max_score == 0.0:
        # If there are vulnerabilities but absolutely no severity metrics provided by the source
        severity_label = "UNKNOWN"

    return severity_label, max_score, cve_ids_with_scores


def query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> Dict:
    """
    Query the OSV API for vulnerabilities affecting a specific package version.

    Args:
        package_name: Name of the package.
        version: Installed version string.
        ecosystem: Package ecosystem (e.g., 'PyPI', 'npm', 'Go', 'Maven').

    Returns:
        OSV API response dict (contains 'vulns' key if vulnerabilities found).
    """
    # Translate our ecosystem name to OSV's expected identifier
    osv_ecosystem = get_osv_ecosystem(ecosystem)

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": osv_ecosystem,
        },
        "version": version,
    }

    try:
        response = requests.post(
            OSV_API_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 200:
            return response.json()
        return {}

    except requests.RequestException:
        return {}


def scan_all_packages(packages: List[Dict]) -> Dict[str, Dict]:
    """
    Scan all packages for known vulnerabilities via the OSV API.
    Dynamically passes the correct ecosystem for each package.

    Args:
        packages: List of package dicts (must have 'name', 'version', and optionally 'ecosystem' keys).

    Returns:
        Dict mapping package name -> vulnerability info dict with keys:
            severity, cvss_score, cve_ids, vuln_count, vulnerabilities.
    """
    console.print(step_header(4, "VULNERABILITY SCAN (OSV - Multi-Ecosystem)", "|>"))

    # Count ecosystems for display
    eco_counts: Dict[str, int] = {}
    for pkg in packages:
        eco = pkg.get("ecosystem", "PyPI")
        eco_counts[eco] = eco_counts.get(eco, 0) + 1

    eco_summary = ", ".join(f"{eco}: {count}" for eco, count in sorted(eco_counts.items()))
    console.print(f"  [dim]Querying OSV database for[/] [bold]{len(packages)}[/] [dim]packages across[/] [bold]{len(eco_counts)}[/] [dim]ecosystems[/]")
    console.print(f"  [dim]Breakdown: {eco_summary}[/]")

    results: Dict[str, Dict] = {}

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="bright_black", complete_style="bold cyan", finished_style="bold green"),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("  Scanning", total=len(packages))

        for pkg in packages:
            name = pkg["name"]
            version = pkg["version"]
            ecosystem = pkg.get("ecosystem", "PyPI")
            progress.update(task, description=f"  [{ecosystem}] [white]{name}[/]")

            osv_result = query_osv(name, version, ecosystem=ecosystem)
            vulns = osv_result.get("vulns", [])

            if vulns:
                severity, score, cves = _extract_severity_info(vulns)
                results[name] = {
                    "severity": severity,
                    "cvss_score": score,
                    "cve_ids": cves,
                    "vuln_count": len(vulns),
                    "vulnerabilities": vulns,
                }
            else:
                results[name] = {
                    "severity": "NONE",
                    "cvss_score": 0.0,
                    "cve_ids": [],
                    "vuln_count": 0,
                    "vulnerabilities": [],
                }

            progress.update(task, advance=1)
            time.sleep(OSV_RATE_LIMIT_DELAY)

    # ── Build Vulnerability Results Table ──
    vuln_table = Table(
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        padding=(0, 1),
        show_lines=True,
        expand=False,
    )
    vuln_table.add_column("#", style="dim", width=4, justify="right")
    vuln_table.add_column("Package", style="bold white", min_width=20)
    vuln_table.add_column("Ecosystem", style="bold magenta", justify="center", min_width=12)
    vuln_table.add_column("Version", style="cyan", justify="center", min_width=10)
    vuln_table.add_column("Severity", justify="center", min_width=12)
    vuln_table.add_column("CVSS", justify="center", min_width=6)
    vuln_table.add_column("Vuln Count", justify="center", min_width=10)
    vuln_table.add_column("CVE IDs", min_width=28)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    sorted_names = sorted(
        results.keys(),
        key=lambda n: severity_order.get(results[n]["severity"], 5)
    )

    idx = 0
    for name in sorted_names:
        info = results[name]
        severity = info["severity"]
        idx += 1

        sev_style = SEVERITY_STYLES.get(severity, "white")
        sev_icon = SEVERITY_ICONS.get(severity, "")
        sev_display = f"[{sev_style}]{sev_icon} {severity}[/]"

        cvss_val = info["cvss_score"]
        if cvss_val >= 9.0:
            cvss_display = f"[bold red]{cvss_val:.1f}[/]"
        elif cvss_val >= 7.0:
            cvss_display = f"[red]{cvss_val:.1f}[/]"
        elif cvss_val >= 4.0:
            cvss_display = f"[yellow]{cvss_val:.1f}[/]"
        elif cvss_val > 0:
            cvss_display = f"[blue]{cvss_val:.1f}[/]"
        else:
            cvss_display = "[dim]0.0[/]"

        vuln_count_val = info["vuln_count"]
        if vuln_count_val > 0:
            vuln_count_display = f"[bold red]{vuln_count_val}[/]"
        else:
            vuln_count_display = "[dim green]0[/]"

        cves = info.get("cve_ids", [])
        if len(cves) > 3:
            cve_display = ", ".join(cves[:3]) + f" (+{len(cves) - 3} more)"
        elif cves:
            cve_display = ", ".join(cves)
        else:
            cve_display = "[dim]--[/]"

        # Find matching pkg ecosystem and version
        pkg_version = "?"
        pkg_ecosystem = "?"
        for p in packages:
            if p["name"] == name:
                pkg_version = p["version"]
                pkg_ecosystem = p.get("ecosystem", "PyPI")
                break

        vuln_table.add_row(
            str(idx), name, pkg_ecosystem, pkg_version,
            sev_display, cvss_display, vuln_count_display, cve_display
        )

    # Count stats
    vuln_count_total = sum(1 for v in results.values() if v["vuln_count"] > 0)
    critical = sum(1 for v in results.values() if v["severity"] == "CRITICAL")
    high = sum(1 for v in results.values() if v["severity"] == "HIGH")
    medium = sum(1 for v in results.values() if v["severity"] == "MEDIUM")

    title_parts = [f"Vulnerability Results  |  {vuln_count_total}/{len(packages)} vulnerable"]
    if critical:
        title_parts.append(f"{critical} CRITICAL")
    if high:
        title_parts.append(f"{high} HIGH")
    if medium:
        title_parts.append(f"{medium} MEDIUM")

    border_color = "red" if critical > 0 else ("yellow" if high > 0 else "cyan")

    console.print(Panel(
        vuln_table,
        title=f"[bold {border_color}]{' | '.join(title_parts)}[/]",
        border_style=border_color,
        padding=(0, 1),
    ))

    # ── Summary Line ──
    if vuln_count_total > 0:
        console.print(
            f"  [bold red][!!] Vulnerabilities detected in {vuln_count_total}/{len(packages)} packages[/]"
        )
        if critical:
            console.print(f"      [bold white on red] {critical} CRITICAL [/]", end="")
        if high:
            console.print(f"  [bold red] {high} HIGH [/]", end="")
        console.print()
    else:
        console.print(
            f"  [bold green][OK] No known vulnerabilities found in {len(packages)} packages[/]"
        )

    return results
