import os
import sys
import json
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional

# Ensure monitor directory is in path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastmcp import FastMCP, Context
from utils.config import MCP_SERVER_NAME, MCP_SERVER_VERSION, REPORT_DIR
from utils.sbom import generate_sbom, parse_sbom
from utils.registry_client import check_all_versions
from utils.vuln_scanner import scan_all_packages, _parse_cvss_vector
from utils.threat_intel import evaluate_malicious_indicators, POPULAR_PACKAGES
from utils.static_analysis import deep_inspect_package, get_package_install_path
from utils.runtime_scanner import get_live_packages
from utils.ecosystem_registry import ECOSYSTEMS
import monitor

# Initialize FastMCP Server
mcp = FastMCP(MCP_SERVER_NAME, version=MCP_SERVER_VERSION)

# ═══════════════════════════════════════════════════════════════
# TOOLS
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
async def generate_sbom_tool(image_name: str, ctx: Context) -> str:
    """Generate a CycloneDX SBOM from a Docker image using Syft."""
    await ctx.report_progress(1, 1, f"Generating SBOM for {image_name}...")
    
    # We use a temporary file for the SBOM
    sbom_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_mcp_sbom.json")
    
    generate_sbom(image_name, sbom_path)
    
    if os.path.exists(sbom_path):
        return f"SBOM generated successfully at {sbom_path}"
    else:
        return "Failed to generate SBOM."

@mcp.tool()
async def scan_vulnerabilities(sbom_path: str, include_os: bool = False, ctx: Context = None) -> Dict[str, Any]:
    """Parse SBOM and scan all packages for known CVEs via OSV."""
    if ctx:
        await ctx.report_progress(1, 2, "Parsing SBOM packages...")
        
    packages = parse_sbom(sbom_path, include_os=include_os)
    
    if ctx:
        await ctx.report_progress(2, 2, f"Scanning {len(packages)} packages for vulnerabilities...")
        
    vuln_results = scan_all_packages(packages)
    return {
        "scanned_packages_count": len(packages),
        "vulnerability_results": vuln_results,
        "packages": packages
    }

@mcp.tool()
async def check_threat_intelligence(packages_json: str, ctx: Context = None) -> Dict[str, Any]:
    """Run multi-database threat intel (OSV MAL-, GHSA, blocklist, typosquat).
    Provide `packages_json` as a JSON string of package dicts.
    """
    packages = json.loads(packages_json)
    if ctx:
        await ctx.report_progress(1, 1, f"Checking threat intelligence for {len(packages)} packages...")
        
    malicious_flags, threat_details = evaluate_malicious_indicators({}, packages)
    
    return {
        "malicious_flags": malicious_flags,
        "threat_details": threat_details
    }

@mcp.tool()
async def deep_static_analysis(package_name: str, package_path: str, ctx: Context = None) -> Dict[str, Any]:
    """Run Tree-sitter AST + regex + Shannon entropy analysis on package source."""
    if ctx:
        await ctx.report_progress(1, 1, f"Running deep static analysis on {package_name} at {package_path}...")
    
    result = deep_inspect_package(package_name, package_path, check_vt=False)
    return result

@mcp.tool()
async def scan_container_live(container_name: str, include_os: bool = False, ctx: Context = None) -> List[Dict[str, Any]]:
    """Extract live package inventory from a running Docker container."""
    if ctx:
        await ctx.report_progress(1, 1, f"Scanning container {container_name} live...")
    
    live_packages = get_live_packages(container_name, include_os=include_os)
    return live_packages

@mcp.tool()
async def check_version_drift(package_name: str, version: str, ecosystem: str, ctx: Context = None) -> Dict[str, Any]:
    """Compare installed vs latest version for a single package."""
    pkg = {"name": package_name, "version": version, "ecosystem": ecosystem}
    if ctx:
        await ctx.report_progress(1, 1, f"Checking version drift for {package_name}...")
        
    latest_versions = check_all_versions([pkg])
    latest = latest_versions.get(package_name, "N/A")
    return {
        "package_name": package_name,
        "installed_version": version,
        "latest_version": latest,
        "is_outdated": latest != "N/A" and latest != version
    }

@mcp.tool()
async def typosquat_check(package_name: str, ecosystem: str) -> Dict[str, Any]:
    """Check if a package name is a typosquat of a popular library."""
    from utils.threat_intel import _check_typosquatting
    is_typo, closest = _check_typosquatting(package_name, ecosystem)
    return {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "is_typosquat": is_typo,
        "closest_match": closest
    }

@mcp.tool()
async def decode_cvss_vector(vector: str) -> Dict[str, Any]:
    """Decode a raw CVSS v3.1 vector string into readable scores."""
    score = _parse_cvss_vector(vector)
    return {
        "vector": vector,
        "calculated_score": score
    }

@mcp.tool()
async def full_audit(image_name: str, include_os: bool = False, ctx: Context = None) -> Dict[str, Any]:
    """Run the complete Phase 1 pipeline (SBOM -> Vuln -> Threat Intel -> Static -> Report)."""
    if ctx:
        await ctx.report_progress(1, 8, "Generating SBOM...")
        
    sbom_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_mcp_sbom.json")
    generate_sbom(image_name, sbom_path)
    
    if ctx:
        await ctx.report_progress(2, 8, "Parsing packages...")
    packages = parse_sbom(sbom_path, include_os=include_os)
    
    if ctx:
        await ctx.report_progress(3, 8, "Checking version drift...")
    latest_versions = check_all_versions(packages)
    
    if ctx:
        await ctx.report_progress(4, 8, "Scanning for vulnerabilities (OSV)...")
    vuln_results = scan_all_packages(packages)
    
    if ctx:
        await ctx.report_progress(5, 8, "Evaluating threat intelligence...")
    malicious_flags, threat_details = evaluate_malicious_indicators(vuln_results, packages)
    
    if ctx:
        await ctx.report_progress(6, 8, "Deep static analysis on clean packages...")
    
    inspection_map = {}
    known_malicious = {name for name, flagged in malicious_flags.items() if flagged}
    clean_packages = [
        pkg for pkg in packages 
        if pkg["name"] not in known_malicious 
        and not monitor._is_popular_package(pkg["name"], pkg.get("ecosystem", "PyPI"))
    ]
    
    for pkg in clean_packages:
        pkg_path = get_package_install_path(pkg["name"], pkg.get("ecosystem", "PyPI"))
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
                result["scan_results"].get("ast_findings")
            ):
                inspection_map[pkg["name"]] = result
                
                if result["scan_results"].get("ast_findings"):
                    malicious_flags[pkg["name"]] = True
                    threat_details[pkg["name"]] = threat_details.get(pkg["name"], []) + ["Zero-Day: Deep Scan detected Behavioral AST IOCs"]
    
    if ctx:
        await ctx.report_progress(7, 8, "Building audit data...")
    
    audit_data = monitor._build_audit_data(packages, latest_versions, vuln_results, malicious_flags, threat_details, inspection_map)
    
    if ctx:
        await ctx.report_progress(8, 8, "Generating report...")
    
    from utils.report import generate_excel_report
    report_path = generate_excel_report(audit_data, REPORT_DIR)
    
    return {
        "image_name": image_name,
        "packages_scanned": len(packages),
        "malicious_packages": [d["package"] for d in audit_data if d.get("is_malicious")],
        "critical_vulns": [d["package"] for d in audit_data if d["severity"] == "CRITICAL"],
        "report_path": report_path,
        "threat_details": threat_details,
        "deep_analysis_findings": inspection_map
    }

# ═══════════════════════════════════════════════════════════════
# RESOURCES
# ═══════════════════════════════════════════════════════════════

@mcp.resource("sentinel://config")
def get_config() -> str:
    """Current Sentinel configuration."""
    from utils.config import SEVERITY_THRESHOLDS, PYPI_API_BASE, OSV_API_URL
    return json.dumps({
        "server_name": MCP_SERVER_NAME,
        "version": MCP_SERVER_VERSION,
        "severity_thresholds": SEVERITY_THRESHOLDS,
        "pypi_api": PYPI_API_BASE,
        "osv_api": OSV_API_URL
    }, indent=2)

@mcp.resource("sentinel://ecosystems")
def get_ecosystems() -> str:
    """Registry of all supported ecosystems."""
    eco_list = []
    for eco, data in ECOSYSTEMS.items():
        eco_list.append({
            "ecosystem": eco,
            "registry_url": data.get("registry_url"),
            "osv_name": data.get("osv_name")
        })
    return json.dumps(eco_list, indent=2)

@mcp.resource("sentinel://blocklist")
def get_blocklist() -> str:
    """Current local threat blocklist."""
    from utils.threat_intel import LOCAL_BLOCKLIST
    return json.dumps(LOCAL_BLOCKLIST, indent=2)

@mcp.resource("sentinel://scan-history")
def get_scan_history() -> str:
    """Previous scan results from the reports directory."""
    if not os.path.exists(REPORT_DIR):
        return "[]"
    files = []
    for f in os.listdir(REPORT_DIR):
        if f.endswith(".xlsx") or f.endswith(".json"):
            filepath = os.path.join(REPORT_DIR, f)
            files.append({
                "filename": f,
                "created_at": datetime.fromtimestamp(os.path.getctime(filepath)).isoformat(),
                "size_bytes": os.path.getsize(filepath)
            })
    return json.dumps(files, indent=2)

@mcp.resource("sentinel://report/{filename}")
def get_report(filename: str) -> str:
    """Read a specific previously generated audit report."""
    filepath = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(filepath):
        return json.dumps({"error": "Report not found"})
    if filename.endswith(".json"):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    else:
        return json.dumps({"error": f"Cannot read binary/Excel format directly. Use JSON reports or check metadata for {filename}"})

# ═══════════════════════════════════════════════════════════════
# PROMPTS
# ═══════════════════════════════════════════════════════════════

@mcp.prompt()
def security_audit() -> str:
    return """Use the `full_audit` tool to run a complete security audit on a Docker image. 
Alternatively, use `generate_sbom` -> `scan_vulnerabilities` -> `check_threat_intelligence` -> `deep_static_analysis` in sequence. 
Summarize findings as a SOC analyst. Prioritize CRITICAL and MALICIOUS items first. Recommend remediation actions."""

@mcp.prompt()
def investigate_package() -> str:
    return """Deep-dive investigation of one suspicious package.
Use `check_version_drift`, `typosquat_check`, and `deep_static_analysis` on this package. 
If AST findings exist, explain the intent of each flagged code pattern. 
Classify as MALICIOUS / SUSPICIOUS / BENIGN with evidence."""

@mcp.prompt()
def triage_alert() -> str:
    return """Given a runtime change alert, use `scan_container_live` to get the current state, 
then `scan_vulnerabilities` and `check_threat_intelligence` on any new packages. 
Determine if this is a legitimate update or a supply chain injection."""

# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Supply Chain Sentinel MCP Server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio", help="Transport mode")
    parser.add_argument("--port", type=int, default=8080, help="Port for http transport")
    args = parser.parse_args()
    
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        # Check for simple auth token
        auth_token = os.environ.get("SENTINEL_MCP_TOKEN")
        if not auth_token:
            print("WARNING: Running HTTP transport without SENTINEL_MCP_TOKEN set. No authentication will be required.")
        mcp.run(transport="sse", port=args.port)
