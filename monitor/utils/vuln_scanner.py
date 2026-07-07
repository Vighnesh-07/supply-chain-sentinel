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


def _extract_severity_info(vulns: List[Dict]) -> Tuple[str, float, List[str]]:
    """
    Extract the maximum severity and CVE IDs from a list of OSV vulnerabilities.

    Args:
        vulns: List of vulnerability objects from OSV API response.

    Returns:
        Tuple of (severity_label, max_cvss_score, list_of_cve_ids).
    """
    max_score = 0.0
    cve_ids = []

    for vuln in vulns:
        # ── Collect CVE identifiers ──
        vuln_id = vuln.get("id", "")
        aliases = vuln.get("aliases", [])

        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_ids.append(alias)
        if vuln_id.startswith("CVE-"):
            cve_ids.append(vuln_id)

        # ── Extract CVSS score from severity array ──
        severity_list = vuln.get("severity", [])
        for sev in severity_list:
            sev_type = sev.get("type", "")
            score_val = sev.get("score", "")

            # OSV provides CVSS vectors; try to extract the base score
            if sev_type.startswith("CVSS_V3") and isinstance(score_val, str):
                try:
                    numeric = float(score_val)
                    max_score = max(max_score, numeric)
                except ValueError:
                    pass

        # ── Fallback: Check database_specific.severity ──
        db_specific = vuln.get("database_specific", {})
        sev_str = db_specific.get("severity", "").upper()
        if sev_str:
            severity_score_map = {
                "CRITICAL": 9.5,
                "HIGH": 7.5,
                "MODERATE": 5.5,
                "MEDIUM": 5.5,
                "LOW": 2.5,
            }
            mapped = severity_score_map.get(sev_str, 0.0)
            max_score = max(max_score, mapped)

        # ── Fallback: Check ecosystem_specific.severity ──
        eco_specific = vuln.get("ecosystem_specific", {})
        eco_sev = eco_specific.get("severity", "").upper()
        if eco_sev:
            severity_score_map = {
                "CRITICAL": 9.5,
                "HIGH": 7.5,
                "MODERATE": 5.5,
                "MEDIUM": 5.5,
                "LOW": 2.5,
            }
            mapped = severity_score_map.get(eco_sev, 0.0)
            max_score = max(max_score, mapped)

    # Deduplicate CVE IDs while preserving order
    seen_cves = set()
    unique_cves = []
    for cve in cve_ids:
        if cve not in seen_cves:
            seen_cves.add(cve)
            unique_cves.append(cve)

    severity_label = _classify_severity(max_score)
    return severity_label, max_score, unique_cves


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
