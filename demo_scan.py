#!/usr/bin/env python3
"""
Demo script to run the full Sentinel scan (including AI) on demo malware packages.
Set GEMINI_API_KEY environment variable before running for full AI analysis.
"""
import sys
from pathlib import Path

# Add project root to path so we can import Sentinel
sys.path.insert(0, str(Path(__file__).resolve().parent))
from monitor.utils.static_analysis import deep_inspect_package, display_inspection_results
from monitor.utils.ai_analyzer import (
    generate_executive_summary,
    analyze_dependency_risk,
    display_executive_summary,
    display_dependency_risk,
)

# Scan our purpose-built demo malware packages
packages_to_scan = [
    ("wallet-drainer", "demo-packages/wallet-drainer"),
    ("cloud-exfil", "demo-packages/cloud-exfil"),
    ("b64-dropper", "demo-packages/b64-dropper"),
    ("hex-beacon", "demo-packages/hex-beacon"),
    ("webhook-spy", "demo-packages/webhook-spy"),
]

inspections = []
for name, path in packages_to_scan:
    res = deep_inspect_package(name, path, check_abuse_db=False, check_vt=False, run_ai=True)
    inspections.append(res)

print("\n" + "="*80)
print(" SENTINEL DEEP INSPECTION + AI ANALYSIS (DEMO MODE)")
print("="*80)
display_inspection_results(inspections, only_critical=False)

# Generate Executive Summary from all results
summary_input = {
    "packages_scanned": len(packages_to_scan),
    "ecosystems": ["npm"],
    "malicious_packages": [name for name, _ in packages_to_scan],
    "inspection_summaries": {
        insp["package"]: insp.get("risk_summary", "") for insp in inspections
    },
    "ai_intents": {
        insp["package"]: insp.get("ai_results", {}).get("intent_analyses", [])
        for insp in inspections
        if insp.get("ai_results", {}).get("intent_analyses")
    },
}
exec_summary = generate_executive_summary(summary_input)
if exec_summary:
    display_executive_summary(exec_summary)

# Dependency Risk
dep_packages = [{"name": name, "version": "1.0.0", "ecosystem": "npm"} for name, _ in packages_to_scan]
dep_risk = analyze_dependency_risk(dep_packages)
if dep_risk:
    display_dependency_risk(dep_risk)
