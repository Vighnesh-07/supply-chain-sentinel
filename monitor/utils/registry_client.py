"""
Supply Chain Sentinel — Universal Registry Client
====================================================
Queries package registries across all supported ecosystems to
retrieve the latest published version of each package.

Supports: PyPI, npm, RubyGems, Go Proxy, Maven Central,
          crates.io, Packagist, NuGet.
"""

import time
from typing import Optional, Dict, List

import requests

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .config import PYPI_API_BASE, REGISTRY_RATE_LIMIT_DELAY, REQUEST_TIMEOUT, step_header
from .ecosystem_registry import ECOSYSTEMS

console = Console()


# ═══════════════════════════════════════════════════════════════
# INDIVIDUAL REGISTRY LOOKUPS
# ═══════════════════════════════════════════════════════════════

def _get_latest_pypi(package_name: str) -> Optional[str]:
    """Query PyPI for the latest version."""
    url = f"{PYPI_API_BASE}/{package_name}/json"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json().get("info", {}).get("version")
    except requests.RequestException:
        pass
    return None


def _get_latest_npm(package_name: str) -> Optional[str]:
    """Query npm registry for the latest version."""
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            return data.get("dist-tags", {}).get("latest")
    except requests.RequestException:
        pass
    return None


def _get_latest_rubygems(package_name: str) -> Optional[str]:
    """Query RubyGems for the latest version."""
    url = f"https://rubygems.org/api/v1/gems/{package_name}.json"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json().get("version")
    except requests.RequestException:
        pass
    return None


def _get_latest_go(module_name: str) -> Optional[str]:
    """Query Go module proxy for the latest version."""
    url = f"https://proxy.golang.org/{module_name}/@latest"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            version = resp.json().get("Version", "")
            # Strip leading 'v' prefix for display consistency
            return version.lstrip("v") if version else None
    except requests.RequestException:
        pass
    return None


def _get_latest_maven(package_name: str) -> Optional[str]:
    """Query Maven Central for the latest version.
    Package name format is typically 'groupId:artifactId'.
    """
    parts = package_name.split(":")
    if len(parts) == 2:
        group_id, artifact_id = parts
    else:
        # Try treating as artifact name only
        group_id = ""
        artifact_id = package_name

    query = f"a:{artifact_id}"
    if group_id:
        query = f"g:{group_id}+AND+a:{artifact_id}"

    url = f"https://search.maven.org/solrsearch/select?q={query}&rows=1&wt=json"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            docs = resp.json().get("response", {}).get("docs", [])
            if docs:
                return docs[0].get("latestVersion")
    except requests.RequestException:
        pass
    return None


def _get_latest_crates(package_name: str) -> Optional[str]:
    """Query crates.io for the latest stable Rust crate version."""
    url = f"https://crates.io/api/v1/crates/{package_name}"
    try:
        resp = requests.get(
            url, timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "SupplyChainSentinel/1.0"}
        )
        if resp.status_code == 200:
            return resp.json().get("crate", {}).get("max_stable_version")
    except requests.RequestException:
        pass
    return None


def _get_latest_packagist(package_name: str) -> Optional[str]:
    """Query Packagist for the latest PHP package version."""
    url = f"https://repo.packagist.org/p2/{package_name}.json"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            packages = data.get("packages", {}).get(package_name, [])
            if packages:
                # First entry is typically the latest
                return packages[0].get("version", "").lstrip("v")
    except requests.RequestException:
        pass
    return None


def _get_latest_nuget(package_name: str) -> Optional[str]:
    """Query NuGet for the latest .NET package version."""
    url = f"https://api.nuget.org/v3-flatcontainer/{package_name.lower()}/index.json"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            versions = resp.json().get("versions", [])
            if versions:
                return versions[-1]  # Last entry is the latest
    except requests.RequestException:
        pass
    return None


# ═══════════════════════════════════════════════════════════════
# ECOSYSTEM ROUTER
# ═══════════════════════════════════════════════════════════════

_REGISTRY_LOOKUP = {
    "PyPI": _get_latest_pypi,
    "npm": _get_latest_npm,
    "RubyGems": _get_latest_rubygems,
    "Go": _get_latest_go,
    "Maven": _get_latest_maven,
    "crates.io": _get_latest_crates,
    "Packagist": _get_latest_packagist,
    "NuGet": _get_latest_nuget,
}


def get_latest_version(package_name: str, ecosystem: str = "PyPI") -> Optional[str]:
    """
    Query the appropriate registry for the latest version of a package.

    Args:
        package_name: The package name.
        ecosystem: The ecosystem identifier (e.g., 'PyPI', 'npm', 'Go').

    Returns:
        Latest version string, or None if not found / error / unsupported.
    """
    lookup_fn = _REGISTRY_LOOKUP.get(ecosystem)
    if lookup_fn:
        return lookup_fn(package_name)
    return None


# ═══════════════════════════════════════════════════════════════
# BATCH VERSION CHECK
# ═══════════════════════════════════════════════════════════════

def check_all_versions(packages: List[Dict]) -> Dict[str, Optional[str]]:
    """
    Check latest versions for all packages across all ecosystems with a progress bar.

    Args:
        packages: List of package dicts (must have 'name' and 'ecosystem' keys).

    Returns:
        Dict mapping package name -> latest version string (or None).
    """
    console.print(step_header(3, "REGISTRY VERSION CHECK (Multi-Ecosystem)", "|>"))

    # Count packages per ecosystem for display
    eco_counts: Dict[str, int] = {}
    for pkg in packages:
        eco = pkg.get("ecosystem", "PyPI")
        eco_counts[eco] = eco_counts.get(eco, 0) + 1

    eco_summary = ", ".join(f"{eco}: {count}" for eco, count in sorted(eco_counts.items()))
    console.print(f"  [dim]Checking latest releases for[/] [bold]{len(packages)}[/] [dim]packages across[/] [bold]{len(eco_counts)}[/] [dim]ecosystems[/]")
    console.print(f"  [dim]Breakdown: {eco_summary}[/]")

    results: Dict[str, Optional[str]] = {}

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="bright_black", complete_style="bold cyan", finished_style="bold green"),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("  Checking registries", total=len(packages))

        for pkg in packages:
            name = pkg["name"]
            ecosystem = pkg.get("ecosystem", "PyPI")
            progress.update(task, description=f"  [{ecosystem}] [white]{name}[/]")

            latest = get_latest_version(name, ecosystem)
            results[name] = latest

            progress.update(task, advance=1)
            time.sleep(REGISTRY_RATE_LIMIT_DELAY)

    found = sum(1 for v in results.values() if v is not None)
    not_found = len(packages) - found

    # Build a version comparison table
    ver_table = Table(
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        padding=(0, 1),
        show_lines=False,
        expand=False,
    )
    ver_table.add_column("#", style="dim", width=4, justify="right")
    ver_table.add_column("Package", style="bold white", min_width=22)
    ver_table.add_column("Ecosystem", style="bold magenta", justify="center", min_width=14)
    ver_table.add_column("Installed", style="cyan", justify="center", min_width=10)
    ver_table.add_column("Latest", justify="center", min_width=10)
    ver_table.add_column("Status", justify="center", min_width=14)

    outdated_count = 0
    for idx, pkg in enumerate(packages, 1):
        name = pkg["name"]
        current = pkg["version"]
        ecosystem = pkg.get("ecosystem", "PyPI")
        latest = results.get(name)

        if latest is None:
            latest_display = "[dim]N/A[/]"
            status = "[dim]--[/]"
        elif latest != current:
            latest_display = f"[bold green]{latest}[/]"
            status = "[bold yellow]UPDATE AVAIL[/]"
            outdated_count += 1
        else:
            latest_display = f"[green]{latest}[/]"
            status = "[bold green]UP TO DATE[/]"

        ver_table.add_row(str(idx), name, ecosystem, current, latest_display, status)

    console.print(Panel(
        ver_table,
        title=f"[bold cyan]Version Comparison  |  {outdated_count} outdated  |  {len(eco_counts)} ecosystems[/]",
        border_style="cyan",
        padding=(0, 1),
    ))

    console.print(
        f"  [bold green][OK][/] Retrieved versions: "
        f"[bold]{found}[/]/{len(packages)} packages"
    )
    if not_found > 0:
        console.print(f"  [dim yellow][!] {not_found} packages not found on their registries[/]")

    return results
