"""
Supply Chain Sentinel — CI/CD Security Gate
=============================================
Evaluates a SARIF report and enforces security policies in CI/CD pipelines.

Usage:
    python monitor/utils/ci_gate.py <sarif_path> [--fail-on-critical]

Exit Codes:
    0: Gate passed (no blocking findings, or fail-on-critical disabled)
    1: Gate failed (critical findings detected, or SARIF file missing/invalid)
"""

import sys
import os
import json

def main():
    sarif_path = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "monitor/reports/results.sarif"
    fail_on_critical = "--fail-on-critical" in sys.argv

    if not os.path.exists(sarif_path):
        print(f"[!] SARIF file not found at: {sarif_path}")
        github_output = os.environ.get("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a", encoding="utf-8") as fh:
                fh.write("error_count=1\nwarning_count=0\n")
        sys.exit(1)

    try:
        with open(sarif_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"[X] Failed to parse SARIF file: {e}")
        sys.exit(1)

    runs = data.get("runs", [])
    results = runs[0].get("results", []) if runs else []

    errors = sum(1 for r in results if r.get("level") == "error")
    warnings = sum(1 for r in results if r.get("level") == "warning")
    notes = sum(1 for r in results if r.get("level") == "note")
    total = len(results)

    # Print summary
    print("\n" + "=" * 60)
    print("  SUPPLY CHAIN SENTINEL -- CI SECURITY GATE")
    print("=" * 60)
    print(f"  SARIF Report : {sarif_path}")
    print(f"  Total Findings: {total}")
    print(f"  Errors (High/Crit): {errors}")
    print(f"  Warnings         : {warnings}")
    print(f"  Notes / Info     : {notes}")
    print("=" * 60)

    # Write to GitHub Actions outputs if running in CI
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        try:
            with open(github_output, "a", encoding="utf-8") as fh:
                fh.write(f"error_count={errors}\n")
                fh.write(f"warning_count={warnings}\n")
                fh.write(f"note_count={notes}\n")
                fh.write(f"total_findings={total}\n")
        except Exception as e:
            print(f"[!] Warning: could not write to GITHUB_OUTPUT: {e}")

    # Enforce policy gate
    if errors > 0 and fail_on_critical:
        print(f"\n[FAIL] CI Gate Rejected: {errors} critical security finding(s) detected!\n")
        sys.exit(1)

    if errors > 0:
        print(f"\n[!] Warning: {errors} critical finding(s) detected (gate enforcement disabled).\n")
    else:
        print("\n[PASS] CI Gate Approved: No critical security findings.\n")

    sys.exit(0)

if __name__ == "__main__":
    main()
