"""
Supply Chain Sentinel — SBOM Generation & Parsing
===================================================
Generates Software Bill of Materials (SBOM) using Anchore Syft and
parses the CycloneDX JSON output to extract package inventory
across all supported ecosystems.

Supports: Python, Node.js, Go, Ruby, Java, Rust, PHP, .NET, OS packages.
"""

import subprocess
import json
import os
import sys
from typing import List, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import step_header
from .ecosystem_registry import get_ecosystem_by_purl

console = Console()


def generate_sbom(
    image_name: str,
    output_file: str,
    output_format: str = "cyclonedx-json",
) -> str:
    """
    Generate an SBOM for a Docker image using Syft.

    Args:
        image_name: Docker image name/tag to scan (e.g. 'vulnapp:latest').
        output_file: Path to write the generated SBOM JSON.
        output_format: Syft output format (default: cyclonedx-json).

    Returns:
        Path to the generated SBOM file.

    Raises:
        SystemExit: If syft is not installed or the scan fails.
    """
    console.print(step_header(1, "SBOM GENERATION", "|>"))
    console.print(
        f"  [dim]Target:[/] [bold white]{image_name}[/]  "
        f"[dim]| Format:[/] [bold white]{output_format}[/]"
    )

    cmd = [
        "syft",
        image_name,
        "-o", output_format,
        "--file", output_file,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            console.print(f"[bold red]  [X] Syft error:[/]\n{result.stderr.strip()}")
            sys.exit(1)

        if not os.path.exists(output_file):
            console.print("[bold red]  [X] SBOM file was not created by Syft[/]")
            sys.exit(1)

        file_size = os.path.getsize(output_file)
        console.print(
            f"  [bold green][OK][/] SBOM generated successfully\n"
            f"       [dim]File: {output_file} ({file_size:,} bytes)[/]"
        )
        return output_file

    except FileNotFoundError:
        console.print(Panel(
            "[bold red][X] 'syft' command not found![/]\n\n"
            "  Install Syft using one of these methods:\n\n"
            "  [cyan]# Windows (Chocolatey)[/]\n"
            "  choco install syft\n\n"
            "  [cyan]# Windows (Scoop)[/]\n"
            "  scoop install syft\n\n"
            "  [cyan]# Cross-platform (Go Install)[/]\n"
            "  go install github.com/anchore/syft/cmd/syft@latest\n\n"
            "  [cyan]# Or download from GitHub Releases:[/]\n"
            "  https://github.com/anchore/syft/releases",
            title="[bold red]Installation Required[/]",
            border_style="red",
            padding=(1, 2),
        ))
        sys.exit(1)

    except subprocess.TimeoutExpired:
        console.print("[bold red]  [X] SBOM generation timed out (300s limit)[/]")
        sys.exit(1)


def parse_sbom(sbom_file: str, include_os: bool = False) -> List[Dict]:
    """
    Parse a CycloneDX JSON SBOM and extract packages from ALL supported ecosystems.

    Args:
        sbom_file: Path to the CycloneDX JSON SBOM file.
        include_os: If True, include OS-level packages (deb, apk, rpm).

    Returns:
        List of dicts with keys: name, version, purl, type, ecosystem.
    """
    console.print(step_header(2, "SBOM PARSING (Multi-Ecosystem)", "|>"))
    console.print(f"  [dim]Source:[/] [bold white]{sbom_file}[/]")

    with open(sbom_file, "r", encoding="utf-8") as f:
        sbom_data = json.load(f)

    packages = []
    seen = set()  # Deduplicate by (name, version, ecosystem)
    components = sbom_data.get("components", [])
    skipped_os = 0
    skipped_unknown = 0

    for component in components:
        purl = component.get("purl", "")
        name = component.get("name", "")
        version = component.get("version", "unknown")

        if not name:
            continue

        # ── Detect ecosystem from PURL ──
        ecosystem = None
        if purl:
            ecosystem = get_ecosystem_by_purl(purl, include_os=include_os)

            if ecosystem is None:
                # Check if it's an OS package we're skipping
                os_eco = get_ecosystem_by_purl(purl, include_os=True)
                if os_eco and not include_os:
                    skipped_os += 1
                    continue
                else:
                    skipped_unknown += 1
                    continue
        else:
            # No PURL — check component type for libraries/frameworks
            comp_type = component.get("type", "")
            if comp_type not in ("library", "framework"):
                continue
            # Default to PyPI for backward compatibility with older SBOMs
            ecosystem = "PyPI"

        # Deduplicate
        key = (name.lower(), version, ecosystem)
        if key in seen:
            continue
        seen.add(key)

        packages.append({
            "name": name,
            "version": version,
            "purl": purl,
            "type": component.get("type", "library"),
            "ecosystem": ecosystem,
        })

    # Sort by ecosystem then name for consistent output
    packages.sort(key=lambda p: (p["ecosystem"], p["name"].lower()))

    # ── Summary ──
    eco_counts: Dict[str, int] = {}
    for pkg in packages:
        eco = pkg["ecosystem"]
        eco_counts[eco] = eco_counts.get(eco, 0) + 1

    eco_summary = ", ".join(f"{eco}: {count}" for eco, count in sorted(eco_counts.items()))

    console.print(
        f"  [bold green][OK][/] Extracted [bold]{len(packages)}[/] packages "
        f"across [bold]{len(eco_counts)}[/] ecosystems "
        f"[dim](from {len(components)} total components)[/]"
    )
    if eco_summary:
        console.print(f"  [dim]Breakdown: {eco_summary}[/]")
    if skipped_os > 0:
        console.print(f"  [dim yellow][!] Skipped {skipped_os} OS-level packages (use --include-os to include)[/]")
    if skipped_unknown > 0:
        console.print(f"  [dim]{skipped_unknown} components with unrecognized ecosystems skipped[/]")

    # Show a mini inventory table grouped by ecosystem
    if packages:
        inv_table = Table(
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            padding=(0, 1),
            show_lines=False,
            expand=False,
        )
        inv_table.add_column("#", style="dim", width=4, justify="right")
        inv_table.add_column("Package", style="bold white", min_width=25)
        inv_table.add_column("Ecosystem", style="bold magenta", justify="center", min_width=14)
        inv_table.add_column("Version", style="cyan", justify="center", min_width=12)

        for idx, pkg in enumerate(packages, 1):
            inv_table.add_row(str(idx), pkg["name"], pkg["ecosystem"], pkg["version"])

        console.print(Panel(
            inv_table,
            title=f"[bold cyan]Package Inventory  |  {len(eco_counts)} Ecosystems[/]",
            border_style="cyan",
            padding=(0, 1),
        ))

    return packages
