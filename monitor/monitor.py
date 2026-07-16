#!/usr/bin/env python3
"""
Supply Chain Sentinel — Multi-Ecosystem SBOM Generation, Dependency Auditing
           & Real-Time Runtime Container Monitoring
==========================================================================

This script orchestrates the complete monitoring pipeline:

  1. Generate an SBOM from a Docker image using Syft (CycloneDX JSON)
  2. Parse the SBOM to extract packages across ALL ecosystems
  3. Query package registries for the latest available versions
  4. Scan for known vulnerabilities via the OSV API (multi-ecosystem)
  5. Evaluate threat intelligence across multiple databases
  6. Display color-coded results in the terminal (Rich)
  7. Export a professionally formatted Excel (.xlsx) report
  8. (Phase 2) Continuously monitor running containers for live changes

Supported Ecosystems:
    Python (PyPI), Node.js (npm), Go, Ruby (RubyGems), Java (Maven),
    Rust (crates.io), PHP (Packagist), .NET (NuGet), OS packages (opt-in)

Threat Intelligence Sources:
    Google OSV (MAL-), GitHub Advisory (GHSA-), Local Blocklist

Usage:
    python monitor.py                                 # Defaults: vulnapp:latest
    python monitor.py --image myapp:v2                # Custom image
    python monitor.py --skip-sbom --sbom-file my.json # Use existing SBOM
    python monitor.py --report-dir ./output            # Custom report directory
    python monitor.py --container vulnapp --watch      # Live runtime watcher
    python monitor.py --container all --watch          # Watch all containers
    python monitor.py --container c1,c2                # Scan specific containers
    python monitor.py --include-os                     # Include OS-level packages

Prerequisites:
    - Docker (running, with the target image built)
    - Syft CLI (https://github.com/anchore/syft)
    - Python packages listed in monitor/requirements.txt
"""

import argparse
import os
import sys
from datetime import datetime
import time

# ── Ensure the monitor package root is importable ──
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config import BANNER, DEFAULT_IMAGE_NAME, SBOM_OUTPUT_FILE, REPORT_DIR, RUNTIME_LOG_FILE, step_header
from utils.sbom import generate_sbom, parse_sbom
from utils.runtime_scanner import get_live_packages, get_all_running_containers
from utils.registry_client import check_all_versions
from utils.vuln_scanner import scan_all_packages
from utils.threat_intel import evaluate_malicious_indicators, POPULAR_PACKAGES
from utils.static_analysis import deep_inspect_package, display_inspection_results, get_package_install_path
from utils.ai_analyzer import (
    generate_executive_summary,
    analyze_dependency_risk,
    display_executive_summary,
    display_dependency_risk,
)
from utils.runtime_network import (
    get_container_sockets, display_network_report, get_threat_sockets, summarize_sockets,
    get_network_attribution_logs, correlate_attribution, display_attribution_summary,
    run_evasion_analysis, display_evasion_report,
)
from utils.report import display_terminal_summary, generate_excel_report

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule

console = Console()


def _is_popular_package(name: str, ecosystem: str) -> bool:
    """Check if a package is a well-known popular library to avoid deep-scanning noise."""
    norm_name = name.lower()
    clean_name = norm_name.split('/')[-1] if '/' in norm_name else norm_name
    
    # Check ecosystem-specific popular list
    popular_set = {p.lower() for p in POPULAR_PACKAGES.get(ecosystem, set())}
    if norm_name in popular_set or clean_name in popular_set:
        return True
        
    # Extra fallback for common tooling packages
    common_clean = {
        "pip", "setuptools", "packaging", "pyparsing", "wheel", "distlib", 
        "pygments", "requests", "urllib3", "certifi", "idna", "charset-normalizer",
        "react", "react-dom", "express", "vite", "plugin-react", "postcss", 
        "autoprefixer", "tailwindcss", "typescript"
    }
    if norm_name in common_clean or clean_name in common_clean:
        return True
        
    return False


# ═══════════════════════════════════════════════════════════════
# CLI ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Supply Chain Sentinel — Multi-Ecosystem SBOM & Dependency Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python monitor.py
  python monitor.py --image vulnapp:latest
  python monitor.py --skip-sbom --sbom-file existing_sbom.json
  python monitor.py --report-dir C:/reports
  python monitor.py --container vulnapp --watch
  python monitor.py --container all --watch
  python monitor.py --include-os
        """,
    )
    parser.add_argument(
        "--image",
        default=DEFAULT_IMAGE_NAME,
        help=f"Docker image to scan (default: {DEFAULT_IMAGE_NAME})",
    )
    parser.add_argument(
        "--report-dir",
        default=None,
        help=f"Directory for output reports (default: {REPORT_DIR})",
    )
    parser.add_argument(
        "--sbom-file",
        default=None,
        help=f"Path to save/load SBOM JSON (default: {SBOM_OUTPUT_FILE})",
    )
    parser.add_argument(
        "--skip-sbom",
        action="store_true",
        help="Skip SBOM generation and use an existing SBOM file",
    )
    parser.add_argument(
        "--container",
        default=None,
        help="Name/ID of running container(s) to scan live. Comma-separated or 'all'.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Run continuously in watch mode (requires --container)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Polling interval in seconds for watch mode (default: 10)",
    )
    parser.add_argument(
        "--include-os",
        action="store_true",
        help="Include OS-level packages (dpkg/apk/rpm) in scans",
    )
    parser.add_argument(
        "--net-monitor",
        action="store_true",
        help="Enable runtime network monitoring (capture active TCP/UDP sockets inside containers)",
    )
    return parser.parse_args()


# ═══════════════════════════════════════════════════════════════
# HELPER: BUILD AUDIT DATA
# ═══════════════════════════════════════════════════════════════

def _build_audit_data(packages, latest_versions, vuln_results, malicious_flags, threat_details, inspection_map=None):
    """Build the unified audit_data list from all pipeline outputs."""
    if inspection_map is None:
        inspection_map = {}
    audit_data = []
    for pkg in packages:
        name = pkg["name"]
        vuln_info = vuln_results.get(name, {})
        inspection = inspection_map.get(name, {})
        scan = inspection.get("scan_results", {})
        abuse = inspection.get("abuseipdb_results", [])

        # Flatten IOC findings for the report
        ioc_urls = [u["value"] for u in scan.get("urls", [])]
        ioc_ips = [i["value"] for i in scan.get("ips", [])]
        ioc_b64 = [b["value"] for b in scan.get("base64_strings", [])]
        ioc_hex = [h["value"] for h in scan.get("hex_strings", [])]
        ioc_firebase = [f"{f['type']}: {f['value']}" for f in scan.get("firebase_findings", [])]
        ioc_s3 = [s["value"] for s in scan.get("s3_buckets", [])]
        ioc_sens = [f"{s['type']}: {s['value']}" for s in scan.get("sensitive_strings", [])]
        ioc_ast = [a for a in scan.get("ast_findings", [])]
        ioc_wallets = [w["value"] for w in scan.get("crypto_wallets", [])]
        ioc_entropy_secrets = [s["value"] for s in scan.get("high_entropy_secrets", [])]
        
        abuse_scores = [
            f"{r['ip']}={r['abuse_confidence_score']}%"
            for r in abuse if r.get("abuse_confidence_score", -1) >= 0
        ]

        audit_data.append({
            "package": name,
            "ecosystem": pkg.get("ecosystem", "PyPI"),
            "current_version": pkg["version"],
            "latest_version": latest_versions.get(name, "N/A"),
            "severity": vuln_info.get("severity", "NONE"),
            "cvss_score": vuln_info.get("cvss_score", 0.0),
            "cve_ids": vuln_info.get("cve_ids", []),
            "vuln_count": vuln_info.get("vuln_count", 0),
            "is_malicious": malicious_flags.get(name, False),
            "threat_sources": threat_details.get(name, []),
            "ioc_urls": ioc_urls,
            "ioc_ips": ioc_ips,
            "ioc_base64": ioc_b64,
            "ioc_hex": ioc_hex,
            "ioc_firebase": ioc_firebase,
            "ioc_s3": ioc_s3,
            "ioc_sens": ioc_sens,
            "ioc_ast": ioc_ast,
            "ioc_wallets": ioc_wallets,
            "ioc_entropy_secrets": ioc_entropy_secrets,
            "abuseipdb_scores": abuse_scores,
            "risk_summary": inspection.get("risk_summary", ""),
        })
    return audit_data


# ═══════════════════════════════════════════════════════════════
# PHASE 1 PIPELINE
# ═══════════════════════════════════════════════════════════════

def run_phase1(
    image_name: str,
    sbom_file: str,
    report_dir: str,
    skip_sbom: bool = False,
    include_os: bool = False,
):
    """
    Execute the complete Phase 1 audit pipeline.
    """
    console.print(BANNER)

    config_table = Table(show_header=False, border_style="cyan", padding=(0, 2), expand=False)
    config_table.add_column("Key", style="bold cyan", min_width=18)
    config_table.add_column("Value", style="bold white")
    config_table.add_row("Target Image", image_name)
    config_table.add_row("SBOM Output", sbom_file)
    config_table.add_row("Report Dir", report_dir)
    config_table.add_row("Skip SBOM", str(skip_sbom))
    config_table.add_row("Include OS Pkgs", str(include_os))
    config_table.add_row("Timestamp", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    config_table.add_row("Mode", "Static Image Scan (Multi-Ecosystem)")

    console.print(Panel(
        config_table,
        title="[bold cyan]Scan Configuration[/]",
        border_style="cyan",
        padding=(1, 2),
    ))

    # Step 1: Generate SBOM
    if not skip_sbom:
        generate_sbom(image_name, sbom_file)
    else:
        if not os.path.exists(sbom_file):
            console.print(
                f"[bold red]  [X] SBOM file not found:[/] {sbom_file}\n"
                f"      Run without --skip-sbom to generate a fresh SBOM."
            )
            sys.exit(1)
        console.print(
            f"\n  [bold yellow][>>] Skipping SBOM generation -- using existing file:[/] {sbom_file}"
        )

    # Step 2: Parse SBOM (multi-ecosystem)
    packages = parse_sbom(sbom_file, include_os=include_os)

    if not packages:
        console.print(
            "[bold yellow]  [!] No packages found in SBOM.[/]\n"
            "      Ensure the Docker image has installed packages."
        )
        sys.exit(0)

    # Step 3: Check latest versions across all registries
    latest_versions = check_all_versions(packages)

    # Step 4: Scan for vulnerabilities (OSV API - multi-ecosystem)
    vuln_results = scan_all_packages(packages)

    # Step 5: Threat Intelligence (multi-database)
    malicious_flags, threat_details = evaluate_malicious_indicators(vuln_results, packages)

    # Step 5.5: Deep Static Analysis — scan CLEAN packages to find unknown threats
    # Known-malicious packages are already flagged by OSV/advisories, no need to look inside.
    # The real value is scanning "clean" packages for hidden URLs, IPs, Base64 payloads.
    console.print(step_header("5.5", "DEEP STATIC ANALYSIS (Zero-Day IOC Hunt)", "|>"))
    inspection_map = {}
    known_malicious = {name for name, flagged in malicious_flags.items() if flagged}
    clean_packages = [
        pkg for pkg in packages 
        if pkg["name"] not in known_malicious 
        and not _is_popular_package(pkg["name"], pkg.get("ecosystem", "PyPI"))
    ]
    if clean_packages:
        console.print(f"  [dim]Scanning[/] [bold cyan]{len(clean_packages)}[/] [dim]clean package(s) for hidden URLs, IPs, Base64 payloads...[/]")
        if known_malicious:
            console.print(f"  [dim]Skipping {len(known_malicious)} already-flagged package(s): {', '.join(known_malicious)}[/]")
        scanned = 0
        for pkg in clean_packages:
            pkg_path = get_package_install_path(pkg["name"], pkg.get("ecosystem", "PyPI"))
            if pkg_path:
                result = deep_inspect_package(pkg["name"], pkg_path)
                # Only store if IOCs were actually found
                if result.get("scan_results") and (
                    result["scan_results"].get("urls") or
                    result["scan_results"].get("ips") or
                    result["scan_results"].get("base64_strings") or
                    result["scan_results"].get("hex_strings") or
                    result["scan_results"].get("firebase_findings") or
                    result["scan_results"].get("s3_buckets") or
                    result["scan_results"].get("sensitive_strings") or
                    result["scan_results"].get("ast_findings")
                ):
                    inspection_map[pkg["name"]] = result
                    
                    if result["scan_results"].get("ast_findings"):
                        is_malicious = True
                        ai_res = result.get("ai_results", {})
                        if ai_res and ai_res.get("ai_available", False):
                            intents = ai_res.get("intent_analyses", [])
                            if intents:
                                if all(intent.get("verdict") == "BENIGN" for intent in intents):
                                    is_malicious = False
                        if is_malicious:
                            malicious_flags[pkg["name"]] = True
                            threat_details[pkg["name"]] = threat_details.get(pkg["name"], []) + ["Zero-Day: Deep Scan detected Behavioral AST IOCs"]
                scanned += 1
        console.print(f"  [bold green][OK][/] Scanned {scanned}/{len(clean_packages)} packages")
        if inspection_map:
            console.print(f"  [bold red][!!] Suspicious IOCs found in {len(inspection_map)} package(s)![/]")
            display_inspection_results(list(inspection_map.values()))
        else:
            console.print(f"  [bold green][OK] No hidden IOCs detected in any clean packages.[/]")
    else:
        console.print(f"  [bold yellow][!] All packages already flagged — no clean packages to deep-scan.[/]")

    audit_data = _build_audit_data(packages, latest_versions, vuln_results, malicious_flags, threat_details, inspection_map)

    console.print(step_header(6, "AUDIT RESULTS & DASHBOARD", "|>"))
    display_terminal_summary(audit_data)

    console.print(step_header(7, "REPORT GENERATION", "|>"))
    report_path = generate_excel_report(audit_data, report_dir)

    # Step 8: AI Intelligence (Layer 6)
    console.print(step_header(8, "AI INTELLIGENCE ENGINE (Layer 6)", "|>"))
    try:
        # Dependency Risk Analysis
        dep_risk = analyze_dependency_risk(packages)
        if dep_risk:
            display_dependency_risk(dep_risk)

        # Executive Summary -- feed all raw scan data to the AI SOC analyst
        summary_input = {
            "packages_scanned": len(packages),
            "ecosystems": list(set(p.get("ecosystem", "Unknown") for p in packages)),
            "malicious_packages": [d["package"] for d in audit_data if d.get("is_malicious")],
            "critical_vulns": [d["package"] for d in audit_data if d["severity"] == "CRITICAL"],
            "high_vulns": [d["package"] for d in audit_data if d["severity"] == "HIGH"],
            "threat_details": {k: v for k, v in threat_details.items() if v},
            "inspection_summaries": {
                k: v.get("risk_summary", "") for k, v in inspection_map.items()
            },
            "ai_intents": {
                k: v.get("ai_results", {}).get("intent_analyses", [])
                for k, v in inspection_map.items()
                if v.get("ai_results", {}).get("intent_analyses")
            },
        }
        exec_summary = generate_executive_summary(summary_input)
        if exec_summary:
            display_executive_summary(exec_summary)
    except Exception as e:
        console.print(f"  [dim yellow]AI analysis skipped: {e}[/]")

    return audit_data, report_path


# ═══════════════════════════════════════════════════════════════
# PHASE 2 ENHANCEMENT: RUNTIME WATCH
# ═══════════════════════════════════════════════════════════════

def run_live_watch(container_names: list, interval: int, include_os: bool = False, net_monitor: bool = False):
    """Run continuously, polling multiple containers for package changes."""
    console.print(BANNER)

    config_table = Table(show_header=False, border_style="cyan", padding=(0, 2), expand=False)
    config_table.add_column("Key", style="bold cyan", min_width=18)
    config_table.add_column("Value", style="bold white")
    config_table.add_row("Target Containers", ", ".join(container_names))
    config_table.add_row("Polling Interval", f"{interval}s")
    config_table.add_row("Include OS Pkgs", str(include_os))
    config_table.add_row("Log File", str(RUNTIME_LOG_FILE))
    config_table.add_row("Net Monitor", "[bold green]ENABLED[/]" if net_monitor else "[dim]Disabled[/]")
    config_table.add_row("Mode", "Live Runtime Watcher (Multi-Ecosystem)")
    config_table.add_row("Started At", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    console.print(Panel(
        config_table,
        title="[bold cyan]Live Runtime Scanner Active[/]",
        border_style="cyan",
        padding=(1, 2),
    ))

    console.print(f"\n  [bold bright_cyan][>>] Monitoring started. Press Ctrl+C to stop.[/]")
    console.print(f"  [dim]Polling every {interval}s for package changes in {len(container_names)} container(s)...[/]\n")

    os.makedirs(os.path.dirname(RUNTIME_LOG_FILE), exist_ok=True)

    # Track previous state individually per container (Initialize empty to scan everything on startup)
    previous_packages = {c: {} for c in container_names}
    scan_count = 0

    try:
        while True:
            scan_count += 1
            timestamp = datetime.now().strftime('%H:%M:%S')

            for container_name in container_names:
                with console.status(f"[bold cyan]Polling container '{container_name}' (Scan #{scan_count})...[/]", spinner="aesthetic"):
                    # 1. Fetch live packages for this container (multi-ecosystem)
                    live_packages = get_live_packages(container_name, include_os=include_os)
                
                if not live_packages:
                    console.print(f"  [dim]{timestamp} | Scan #{scan_count} | Container '{container_name}' offline or no packages found[/]")
                    continue

                current_packages = {f"{p['ecosystem']}:{p['name']}": p["version"] for p in live_packages}

                # Detect changes
                new_or_updated = []
                for pkg in live_packages:
                    key = f"{pkg['ecosystem']}:{pkg['name']}"
                    if key not in previous_packages[container_name] or previous_packages[container_name][key] != pkg["version"]:
                        new_or_updated.append(pkg)

                # Count ecosystems
                eco_set = set(p.get("ecosystem", "?") for p in live_packages)

                if not new_or_updated:
                    console.print(f"  [dim]{timestamp} | Scan #{scan_count} | [{container_name}] {len(current_packages)} pkgs ({', '.join(eco_set)}) | No changes[/]")
                else:
                    console.print(Rule(f"[bold yellow]Change Detected at {timestamp} in {container_name}[/]", style="yellow"))
                    console.print(f"  [bold yellow][!!] {len(new_or_updated)} new/updated packages detected in scan #{scan_count}[/]\n")

                    # Scan only the new packages
                    vuln_results = scan_all_packages(new_or_updated)
                    malicious_flags, threat_details = evaluate_malicious_indicators(vuln_results, new_or_updated)

                    # Build a change report table
                    change_table = Table(
                        show_header=True,
                        header_style="bold white on dark_blue",
                        border_style="yellow",
                        show_lines=True,
                        padding=(0, 1),
                        expand=False,
                    )
                    change_table.add_column("#", style="dim", width=4, justify="right")
                    change_table.add_column("Package", style="bold white", min_width=20)
                    change_table.add_column("Ecosystem", style="bold magenta", justify="center", min_width=12)
                    change_table.add_column("Version", style="cyan", justify="center", min_width=10)
                    change_table.add_column("Status", justify="center", min_width=14)
                    change_table.add_column("Severity", justify="center", min_width=12)
                    change_table.add_column("Threat Source", min_width=25)

                    # Deep scan CLEAN new packages for zero-day IOCs
                    known_malicious = {name for name, flagged in malicious_flags.items() if flagged}
                    clean_new = [
                        p for p in new_or_updated 
                        if p["name"] not in known_malicious 
                        and not _is_popular_package(p["name"], p.get("ecosystem", "?"))
                    ]
                    watch_inspection_map = {}
                    if clean_new:
                        console.print(f"  [dim]Deep scanning[/] [bold cyan]{len(clean_new)}[/] [dim]clean new package(s) for hidden IOCs...[/]")
                        for pkg in clean_new:
                            pkg_path = get_package_install_path(pkg["name"], pkg.get("ecosystem", "?"), container_name)
                            if pkg_path:
                                result = deep_inspect_package(pkg["name"], pkg_path, check_vt=False)
                                if result.get("scan_results") and (
                                    result["scan_results"].get("urls") or
                                    result["scan_results"].get("ips") or
                                    result["scan_results"].get("base64_strings") or
                                    result["scan_results"].get("hex_strings") or
                                    result["scan_results"].get("firebase_findings") or
                                    result["scan_results"].get("s3_buckets") or
                                    result["scan_results"].get("sensitive_strings") or
                                    result["scan_results"].get("ast_findings") or
                                    result["scan_results"].get("crypto_wallets") or
                                    result["scan_results"].get("high_entropy_secrets")
                                ):
                                    watch_inspection_map[pkg["name"]] = result
                                    
                                    if result["scan_results"].get("ast_findings"):
                                        is_malicious = True
                                        ai_res = result.get("ai_results", {})
                                        if ai_res and ai_res.get("ai_available", False):
                                            intents = ai_res.get("intent_analyses", [])
                                            if intents:
                                                if all(intent.get("verdict") == "BENIGN" for intent in intents):
                                                    is_malicious = False
                                        if is_malicious:
                                            malicious_flags[pkg["name"]] = True
                                            threat_details[pkg["name"]] = threat_details.get(pkg["name"], []) + ["Zero-Day: Deep Scan detected Behavioral AST IOCs"]
                        if watch_inspection_map:
                            console.print(f"  [bold red][!!] Hidden IOCs found in {len(watch_inspection_map)} 'clean' package(s)![/]")
                            # Print the detailed tables ONLY for critical/malicious items or Base64 payloads
                            display_inspection_results(list(watch_inspection_map.values()), only_critical=True)
                        else:
                            console.print(f"  [bold green][OK] No hidden IOCs in new clean packages.[/]")

                    suspicious_count = 0
                    for idx, pkg in enumerate(new_or_updated, 1):
                        name = pkg["name"]
                        ecosystem = pkg.get("ecosystem", "?")
                        is_mal = malicious_flags.get(name, False)
                        
                        # Only report "Hidden IOCs" if they are actually severe (reduces noise for benign packages with URLs)
                        has_hidden_iocs = False
                        if name in watch_inspection_map:
                            res = watch_inspection_map[name]
                            if (res.get("scan_results", {}).get("ast_findings") or
                                res.get("scan_results", {}).get("base64_strings") or
                                res.get("scan_results", {}).get("hex_strings") or
                                res.get("scan_results", {}).get("firebase_findings") or
                                res.get("scan_results", {}).get("s3_buckets") or
                                res.get("scan_results", {}).get("sensitive_strings") or
                                res.get("scan_results", {}).get("crypto_wallets") or
                                res.get("scan_results", {}).get("high_entropy_secrets") or
                                res.get("scan_results", {}).get("urls") or
                                res.get("scan_results", {}).get("ips")):
                                has_hidden_iocs = True
                            elif any(vt.get("malicious_votes", 0) > 0 for vt in res.get("virustotal_results", [])):
                                has_hidden_iocs = True
                            elif any(ab.get("abuse_confidence_score", 0) >= 25 for ab in res.get("abuseipdb_results", [])):
                                has_hidden_iocs = True

                        vuln_info = vuln_results.get(name, {})
                        severity = vuln_info.get("severity", "NONE")
                        sources = threat_details.get(name, [])

                        if not (is_mal or has_hidden_iocs or severity != "NONE"):
                            continue  # Skip clean/safe packages from the report
                            
                        suspicious_count += 1

                        if is_mal:
                            status = "[bold white on red] MALICIOUS [/]"
                            sev_display = "[bold white on red] CRITICAL [/]"
                            source_display = "\n".join(sources) if sources else "Unknown"
                            
                            alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] CRITICAL ALERT: Malicious package '{name}' ({ecosystem}) installed in {container_name}!"
                            with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                f.write(alert_msg + "\n")
                        elif has_hidden_iocs:
                            # Package was "clean" in databases but has suspicious content!
                            ioc_result = watch_inspection_map[name]
                            status = "[bold white on yellow] SUSPICIOUS [/]"
                            sev_display = "[bold yellow][!!] HIDDEN IOC[/]"
                            source_display = f"Deep Scan: {ioc_result.get('risk_summary', 'IOCs found')}"

                            alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] WARNING: Package '{name}' ({ecosystem}) in {container_name} has hidden IOCs: {ioc_result.get('risk_summary', '')}"
                            with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                f.write(alert_msg + "\n")
                        else:
                            status = "[bold yellow]VULNERABLE[/]"
                            from utils.config import SEVERITY_STYLES, SEVERITY_ICONS
                            sev_style = SEVERITY_STYLES.get(severity, "white")
                            sev_icon = SEVERITY_ICONS.get(severity, "")
                            sev_display = f"[{sev_style}]{sev_icon} {severity}[/]"
                            source_display = ", ".join(sources) if sources else "[dim]--[/]"

                        change_table.add_row(
                            str(suspicious_count), name, ecosystem, pkg['version'], status, sev_display, source_display
                        )

                    if suspicious_count > 0:
                        console.print(Panel(
                            change_table,
                            title=f"[bold yellow]Runtime Change Report: {container_name}  |  Scan #{scan_count} (Suspicious Only)[/]",
                            border_style="yellow",
                            padding=(0, 1),
                        ))
                    else:
                        console.print(Panel(
                            "[bold green]No suspicious or vulnerable packages detected in this update.[/]",
                            title=f"[bold green]Runtime Change Report: {container_name}  |  Scan #{scan_count}[/]",
                            border_style="green",
                            padding=(1, 2),
                        ))

                # ── Network Monitor (watch mode) ──
                if net_monitor:
                    net_sockets = get_container_sockets(container_name)

                    # Attribution: read preload.js logs and correlate
                    attr_logs = get_network_attribution_logs(container_name)
                    if attr_logs:
                        correlate_attribution(net_sockets, attr_logs)

                    threats = get_threat_sockets(net_sockets)
                    if threats:
                        display_network_report(container_name, net_sockets, compact=True)
                        # Log network threats with attribution info
                        for t in threats:
                            pkg_info = f" [pkg={t['attributed_package']}:{t.get('attributed_file','?')}]" if t.get('attributed_package') else ""
                            alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] NET THREAT: {container_name} -> {t['remote_ip']}:{t['remote_port']} ({t['risk']}) State={t['state']}{pkg_info}"
                            with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                f.write(alert_msg + "\n")
                    else:
                        ext_count = len([s for s in net_sockets if s.get('risk') == 'EXTERNAL'])
                        console.print(f"  [dim]{timestamp} | [{container_name}] Net: {len(net_sockets)} sockets, {ext_count} external, 0 threats[/]")

                    # Always show attribution summary if logs exist
                    if attr_logs:
                        display_attribution_summary(container_name, attr_logs)
                        
                        # ── Zero-Day Evasion Analysis (Watch Mode) ──
                        evasion_results = run_evasion_analysis(attr_logs)
                        if evasion_results.get("total_findings", 0) > 0:
                            console.print(f"\n[bold red][!!] EVASION ACTIVITY DETECTED IN WATCH MODE ({container_name})[/]")
                            display_evasion_report(container_name, evasion_results)

                            # Log evasion findings
                            for v in evasion_results.get("allowlist_violations", []):
                                alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L1: {container_name} | {v['package']} -> {v['host']}:{v['port']} (UNAUTHORIZED)"
                                with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                    f.write(alert_msg + "\n")
                            for d in evasion_results.get("suspicious_domains", []):
                                alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L2: {container_name} | {d['package']} -> {d['domain']} (age={d['age_days']}d)"
                                with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                    f.write(alert_msg + "\n")
                            for a in evasion_results.get("dns_anomalies", []):
                                alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L3: {container_name} | {a['package']} -> {a['anomaly_type']}"
                                with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                    f.write(alert_msg + "\n")
                            for r in evasion_results.get("raw_ip_connections", []):
                                alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L4: {container_name} | {r['package']} -> {r['host']}:{r['port']} (RAW_IP)"
                                with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                    f.write(alert_msg + "\n")
                            for p in evasion_results.get("process_escapes", []):
                                alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L5: {container_name} | {p['package']} -> {p.get('method','?')}('{p.get('command','?')}') [{p.get('severity','?')}]"
                                with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                    f.write(alert_msg + "\n")

                previous_packages[container_name] = current_packages

            # Sleep until next interval
            time.sleep(interval)

    except KeyboardInterrupt:
        console.print(f"\n  [bold yellow][>>] Live scanning stopped by user after {scan_count} scans.[/]")


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def main():
    """Main entry point — parse CLI args and run Phase 1."""
    args = parse_args()

    # Resolve paths relative to the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))

    sbom_file = args.sbom_file or os.path.join(script_dir, SBOM_OUTPUT_FILE)
    if not os.path.isabs(sbom_file):
        sbom_file = os.path.join(script_dir, sbom_file)

    report_dir = args.report_dir or REPORT_DIR
    if not os.path.isabs(report_dir):
        report_dir = os.path.join(script_dir, report_dir)

    include_os = args.include_os
    net_monitor = args.net_monitor

    # Multi-container parsing
    container_names = []
    if args.container:
        if args.container.lower() == "all":
            container_names = get_all_running_containers()
            if not container_names:
                console.print("[bold red]  [X] No running containers found to monitor.[/]")
                sys.exit(1)
            console.print(f"[bold cyan][*] Auto-detected {len(container_names)} running container(s).[/]")
        else:
            container_names = [c.strip() for c in args.container.split(",") if c.strip()]

    if args.container and args.watch:
        run_live_watch(
            container_names=container_names,
            interval=args.interval,
            include_os=include_os,
            net_monitor=net_monitor,
        )
    elif args.container and not args.watch:
        # Run Phase 1 pipeline but against live containers instead of image
        console.print(BANNER)

        config_table = Table(show_header=False, border_style="cyan", padding=(0, 2), expand=False)
        config_table.add_column("Key", style="bold cyan", min_width=18)
        config_table.add_column("Value", style="bold white")
        config_table.add_row("Target Containers", ", ".join(container_names))
        config_table.add_row("Report Dir", report_dir)
        config_table.add_row("Include OS Pkgs", str(include_os))
        config_table.add_row("Timestamp", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        config_table.add_row("Mode", "Live Container Single Scan (Multi-Ecosystem)")

        console.print(Panel(
            config_table,
            title="[bold cyan]Scan Configuration[/]",
            border_style="cyan",
            padding=(1, 2),
        ))

        # Loop over each container and run the full scan sequence
        for idx, c_name in enumerate(container_names, 1):
            evasion_results = None
            console.print(f"\n[bold magenta]================================================================[/]")
            console.print(f"[bold magenta]   SCANNING CONTAINER ({idx}/{len(container_names)}): {c_name}[/]")
            console.print(f"[bold magenta]================================================================[/]\n")

            console.print(step_header(1, f"LIVE PACKAGE EXTRACTION: {c_name}", "|>"))
            packages = get_live_packages(c_name, include_os=include_os)
            if not packages:
                console.print(f"[bold red]  [X] Failed to get live packages for {c_name}. Ensure container is running.[/]")
                continue

            # Count ecosystems
            eco_counts = {}
            for pkg in packages:
                eco = pkg.get("ecosystem", "?")
                eco_counts[eco] = eco_counts.get(eco, 0) + 1
            eco_summary = ", ".join(f"{eco}: {count}" for eco, count in sorted(eco_counts.items()))

            console.print(f"  [bold green][OK][/] Extracted [bold]{len(packages)}[/] packages from '{c_name}'")
            console.print(f"  [dim]Ecosystems: {eco_summary}[/]")

            latest_versions = check_all_versions(packages)
            vuln_results = scan_all_packages(packages)
            malicious_flags, threat_details = evaluate_malicious_indicators(vuln_results, packages)

            # Deep Static Analysis — scan CLEAN packages for unknown/zero-day threats
            console.print(step_header("5.5", f"DEEP STATIC ANALYSIS: {c_name} (Zero-Day IOC Hunt)", "|>"))
            inspection_map = {}
            known_malicious = {name for name, flagged in malicious_flags.items() if flagged}
            clean_packages = [
                pkg for pkg in packages 
                if pkg["name"] not in known_malicious 
                and not _is_popular_package(pkg["name"], pkg.get("ecosystem", "?"))
            ]
            if clean_packages:
                console.print(f"  [dim]Scanning[/] [bold cyan]{len(clean_packages)}[/] [dim]clean package(s) for hidden IOCs...[/]")
                if known_malicious:
                    console.print(f"  [dim]Skipping {len(known_malicious)} already-flagged: {', '.join(known_malicious)}[/]")
                scanned = 0
                for pkg in clean_packages:
                    pkg_path = get_package_install_path(pkg["name"], pkg.get("ecosystem", "PyPI"), c_name)
                    if pkg_path:
                        result = deep_inspect_package(pkg["name"], pkg_path)
                        if result.get("scan_results") and (
                            result["scan_results"].get("urls") or
                            result["scan_results"].get("ips") or
                            result["scan_results"].get("base64_strings") or
                            result["scan_results"].get("hex_strings") or
                            result["scan_results"].get("firebase_findings") or
                            result["scan_results"].get("s3_buckets") or
                            result["scan_results"].get("sensitive_strings") or
                            result["scan_results"].get("ast_findings") or
                            result["scan_results"].get("crypto_wallets") or
                            result["scan_results"].get("high_entropy_secrets")
                        ):
                            inspection_map[pkg["name"]] = result
                            
                            if result["scan_results"].get("ast_findings"):
                                malicious_flags[pkg["name"]] = True
                                threat_details[pkg["name"]] = threat_details.get(pkg["name"], []) + ["Zero-Day: Deep Scan detected Behavioral AST IOCs"]
                        scanned += 1
                console.print(f"  [bold green][OK][/] Scanned {scanned}/{len(clean_packages)} packages")
                if inspection_map:
                    console.print(f"  [bold red][!!] Suspicious IOCs found in {len(inspection_map)} package(s)![/]")
                    display_inspection_results(list(inspection_map.values()))
                else:
                    console.print(f"  [bold green][OK] No hidden IOCs detected in clean packages.[/]")
            else:
                console.print(f"  [bold yellow][!] All packages already flagged — no clean packages to deep-scan.[/]")

            audit_data = _build_audit_data(packages, latest_versions, vuln_results, malicious_flags, threat_details, inspection_map)

            # ── Network Monitor (single-container scan) ──
            if net_monitor:
                console.print(step_header("5.7", f"RUNTIME NETWORK MONITOR: {c_name}", "|>"))
                net_sockets = get_container_sockets(c_name)

                # Attribution: read the preload.js instrumentation log
                attr_logs = get_network_attribution_logs(c_name)
                if attr_logs:
                    console.print(f"  [bold magenta][>>][/] Found [bold]{len(attr_logs)}[/] attribution log entries from preload instrumentation")
                    correlate_attribution(net_sockets, attr_logs)
                else:
                    console.print(f"  [dim]No attribution log found (preload.js not active or no outbound calls yet)[/]")

                if net_sockets:
                    display_network_report(c_name, net_sockets, compact=False)
                    # Log threats with attribution
                    threats = get_threat_sockets(net_sockets)
                    for t in threats:
                        pkg_info = f" [pkg={t['attributed_package']}:{t.get('attributed_file','?')}]" if t.get('attributed_package') else ""
                        alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] NET THREAT: {c_name} -> {t['remote_ip']}:{t['remote_port']} ({t['risk']}) State={t['state']}{pkg_info}"
                        with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                            f.write(alert_msg + "\n")
                else:
                    console.print(f"  [dim]Could not retrieve network sockets from container '{c_name}'[/]")

                # Show the full attribution summary (which packages phoned home)
                if attr_logs:
                    display_attribution_summary(c_name, attr_logs)

                # ── Zero-Day Evasion Analysis (4 Layers) ──
                if attr_logs:
                    console.print(step_header("5.8", f"ZERO-DAY EVASION ANALYSIS: {c_name}", "|>"))
                    evasion_results = run_evasion_analysis(attr_logs)
                    display_evasion_report(c_name, evasion_results)

                    # Log evasion findings
                    if evasion_results.get("total_findings", 0) > 0:
                        for v in evasion_results.get("allowlist_violations", []):
                            alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L1: {c_name} | {v['package']} -> {v['host']}:{v['port']} (UNAUTHORIZED)"
                            with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                f.write(alert_msg + "\n")
                        for d in evasion_results.get("suspicious_domains", []):
                            alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L2: {c_name} | {d['package']} -> {d['domain']} (age={d['age_days']}d)"
                            with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                f.write(alert_msg + "\n")
                        for a in evasion_results.get("dns_anomalies", []):
                            alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L3: {c_name} | {a['package']} -> {a['anomaly_type']}"
                            with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                f.write(alert_msg + "\n")
                        for r in evasion_results.get("raw_ip_connections", []):
                            alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L4: {c_name} | {r['package']} -> {r['host']}:{r['port']} (RAW_IP)"
                            with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                f.write(alert_msg + "\n")
                        for p in evasion_results.get("process_escapes", []):
                            alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] EVASION L5: {c_name} | {p['package']} -> {p.get('method','?')}('{p.get('command','?')}') [{p.get('severity','?')}]"
                            with open(RUNTIME_LOG_FILE, "a", encoding="utf-8") as f:
                                f.write(alert_msg + "\n")

            console.print(step_header(6, f"AUDIT RESULTS & DASHBOARD: {c_name}", "|>"))
            display_terminal_summary(audit_data, evasion_results)

            console.print(step_header(7, f"REPORT GENERATION: {c_name}", "|>"))
            # Make the report filename unique per container
            container_report_dir = os.path.join(report_dir, c_name)
            generate_excel_report(audit_data, container_report_dir)

    else:
        run_phase1(
            image_name=args.image,
            sbom_file=sbom_file,
            report_dir=report_dir,
            skip_sbom=args.skip_sbom,
            include_os=include_os,
        )


if __name__ == "__main__":
    main()
