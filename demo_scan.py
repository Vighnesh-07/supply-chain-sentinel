#!/usr/bin/env python3
import sys
from pathlib import Path

# Add project root to path so we can import Sentinel
sys.path.insert(0, str(Path(__file__).resolve().parent))
from monitor.utils.static_analysis import deep_inspect_package, display_inspection_results

# Scan our purpose-built demo malware packages
packages_to_scan = [
    ("wallet-drainer (Demo Malware)", "demo-packages/wallet-drainer"),
    ("cloud-exfil (Demo Malware)", "demo-packages/cloud-exfil"),
    ("b64-dropper (Demo Malware)", "demo-packages/b64-dropper"),
]

inspections = []
for name, path in packages_to_scan:
    # Run the deep scan without hitting external network limits for the demo
    res = deep_inspect_package(name, path, check_abuse_db=False, check_vt=False)
    inspections.append(res)

print("\n" + "="*80)
print(" SENTINEL LOCAL MALWARE SCAN (DEMO MODE)")
print("="*80)
display_inspection_results(inspections, only_critical=False)
