"""
sarif_exporter.py — Supply Chain Sentinel SARIF 2.1.0 Exporter
================================================================

Converts the audit_data list (output from _build_audit_data() in monitor.py) into a
valid SARIF 2.1.0 JSON document that can be uploaded to GitHub's Code Scanning Alerts
tab via:

    gh code-scanning upload-results --ref HEAD --commit <SHA> --sarif <file.sarif>

SARIF 2.1.0 specification:
    https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html

GitHub SARIF support documentation:
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from rich.console import Console

console = Console()

# ──────────────────────────────────────────────────────────────────────────────
# SARIF 2.1.0 schema URI (required by GitHub)
# ──────────────────────────────────────────────────────────────────────────────
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

# ──────────────────────────────────────────────────────────────────────────────
# Rule catalogue
# ──────────────────────────────────────────────────────────────────────────────

#: All static rule definitions for Supply Chain Sentinel.
#: Each entry: (id, name, short_desc, full_desc, help_uri, default_level, tags)
_RULE_CATALOGUE = [
    (
        "SSC001",
        "KnownCveVulnerability",
        "Known CVE Vulnerability",
        (
            "The package version has a publicly disclosed CVE with an associated CVSS score. "
            "Upgrade to a patched release or apply the vendor-recommended mitigation immediately."
        ),
        "https://osv.dev/",
        "warning",   # overridden to 'error' for CRITICAL/HIGH per result
        ["security", "supply-chain", "vulnerability", "cve"],
    ),
    (
        "SSC002",
        "MaliciousPackageDetected",
        "Malicious Package Detected",
        (
            "The package has been flagged as malicious by one or more threat intelligence sources "
            "(e.g., Google OSV MAL- advisories, GitHub Advisory Database, or a local blocklist). "
            "Remove and quarantine it immediately."
        ),
        "https://osv.dev/",
        "error",
        ["security", "supply-chain", "malware"],
    ),
    (
        "SSC003",
        "TypoSquattingAttack",
        "Typo-Squatting Attack",
        (
            "The package name closely resembles a popular, legitimate package. This is a common "
            "supply-chain attack technique. Verify the package name and publisher before using it."
        ),
        "https://osv.dev/",
        "error",
        ["security", "supply-chain", "typosquatting"],
    ),
    (
        "SSC004",
        "SuspiciousStaticCodeAstIoc",
        "Suspicious Static Code (AST IOC)",
        (
            "Static AST analysis detected behavioural indicators of compromise inside the package "
            "source (e.g., dynamic code execution, obfuscated eval calls, subprocess shell spawning "
            "or network exfiltration patterns). Manual review is strongly advised."
        ),
        "https://github.com/vighnesh/supply-chain-sentinel",
        "warning",
        ["security", "supply-chain", "static-analysis", "ast"],
    ),
    (
        "SSC005",
        "HardcodedCredentialHighEntropySecret",
        "Hardcoded Credential / High-Entropy Secret",
        (
            "A high-entropy string consistent with an API key, access token, private key or other "
            "credential was found embedded inside the package files. This may indicate a backdoored "
            "package or a developer mistake that leaks credentials to all installers."
        ),
        "https://github.com/vighnesh/supply-chain-sentinel",
        "error",
        ["security", "supply-chain", "secrets", "credentials"],
    ),
    (
        "SSC006",
        "CryptoWalletAddressEmbedded",
        "Crypto Wallet Address Embedded",
        (
            "A cryptocurrency wallet address was found hard-coded in the package files. This may "
            "indicate a cryptojacking payload or donation-ware behaviour introduced without the "
            "end-user's knowledge."
        ),
        "https://github.com/vighnesh/supply-chain-sentinel",
        "warning",
        ["security", "supply-chain", "cryptojacking", "wallet"],
    ),
    (
        "SSC007",
        "OutdatedPackage",
        "Outdated Package",
        (
            "A newer version of the package is available. Running outdated packages increases the "
            "attack surface and may miss security patches. Schedule an upgrade during your next "
            "maintenance window."
        ),
        "https://github.com/vighnesh/supply-chain-sentinel",
        "note",
        ["maintenance", "supply-chain", "outdated"],
    ),
    (
        "SSC008",
        "ThreatIntelligenceMatch",
        "Threat Intelligence Match",
        (
            "The package matched one or more threat intelligence sources (e.g., GitHub Advisory "
            "Database, local blocklist, or OSV advisories not classified as malware). "
            "Investigate further before continuing to use this package."
        ),
        "https://github.com/vighnesh/supply-chain-sentinel",
        "error",
        ["security", "supply-chain", "threat-intel"],
    ),
]

# Build a fast lookup: rule_id -> rule_dict
_RULES_BY_ID: Dict[str, Dict] = {}

for (_id, _name, _short, _full, _uri, _level, _tags) in _RULE_CATALOGUE:
    _RULES_BY_ID[_id] = {
        "id": _id,
        "name": _name,
        "shortDescription": {"text": _short},
        "fullDescription": {"text": _full},
        "helpUri": _uri,
        "defaultConfiguration": {"level": _level},
        "properties": {"tags": _tags},
    }


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _fingerprint(rule_id: str, pkg_name: str, version: str, finding: str) -> str:
    """
    Compute a stable fingerprint for a SARIF result.

    The fingerprint is the first 16 hex characters of the SHA-256 digest of
    the concatenation of rule_id, package name, version and finding text,
    separated by null bytes to prevent collisions.

    Args:
        rule_id:  SARIF rule identifier (e.g., ``"SSC001"``).
        pkg_name: Package name.
        version:  Package version string.
        finding:  Short human-readable description of the specific finding.

    Returns:
        16-character hex string suitable for ``fingerprints.primaryLocationLineHash/v1``.
    """
    raw = f"{rule_id}\x00{pkg_name}\x00{version}\x00{finding}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _logical_location(pkg_name: str, ecosystem: str, version: str) -> Dict:
    """
    Build a SARIF ``logicalLocation`` object for a package.

    GitHub's code-scanning UI accepts logical locations when results are not
    tied to a specific source file (e.g., for dependency-level findings).

    Args:
        pkg_name:  Package name.
        ecosystem: Package ecosystem (e.g., ``"PyPI"``, ``"npm"``).
        version:   Package version string.

    Returns:
        A SARIF ``location`` dict containing a ``logicalLocations`` array.
    """
    return {
        "logicalLocations": [
            {
                "name": pkg_name,
                "kind": "module",
                "fullyQualifiedName": f"{ecosystem}/{pkg_name}@{version}",
            }
        ]
    }


def _make_result(
    rule_id: str,
    level: str,
    message: str,
    pkg_name: str,
    ecosystem: str,
    version: str,
    finding_key: str,
) -> Dict:
    """
    Build a single SARIF ``result`` object.

    Args:
        rule_id:     The rule identifier (e.g., ``"SSC001"``).
        level:       One of ``"error"``, ``"warning"``, or ``"note"``.
        message:     Human-readable description of the finding.
        pkg_name:    Package name.
        ecosystem:   Package ecosystem.
        version:     Package version string.
        finding_key: Short string used to differentiate fingerprints for
                     multiple results from the same package/rule pair.

    Returns:
        A fully populated SARIF ``result`` dict.
    """
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [_logical_location(pkg_name, ecosystem, version)],
        "fingerprints": {
            "primaryLocationLineHash/v1": _fingerprint(rule_id, pkg_name, version, finding_key),
        },
        "properties": {
            "ecosystem": ecosystem,
            "package": pkg_name,
            "version": version,
        },
    }


def _severity_to_level(severity: str) -> str:
    """
    Map an OSV/NVD severity string to a SARIF level.

    Args:
        severity: One of ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``,
                  ``"NONE"``, or empty string.

    Returns:
        ``"error"`` for CRITICAL/HIGH, ``"warning"`` for MEDIUM/LOW/unknown,
        ``"note"`` for NONE.
    """
    s = severity.upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s in ("MEDIUM", "LOW"):
        return "warning"
    return "note"


def _git_remote_url(base_dir: str) -> Optional[str]:
    """
    Attempt to read the first ``remote.origin.url`` from a ``.git/config`` file.

    Args:
        base_dir: Directory from which to start searching for a ``.git`` folder.

    Returns:
        The remote URL string, or ``None`` if no git repository was found.
    """
    candidate = base_dir
    for _ in range(4):  # walk up at most 4 levels
        git_config = os.path.join(candidate, ".git", "config")
        if os.path.isfile(git_config):
            try:
                with open(git_config, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        stripped = line.strip()
                        if stripped.startswith("url ="):
                            return stripped.split("=", 1)[1].strip()
            except OSError:
                pass
            return None
        parent = os.path.dirname(candidate)
        if parent == candidate:
            break
        candidate = parent
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def generate_sarif(
    audit_data: List[Dict],
    image_name: str,
    sbom_file: Optional[str] = None,
) -> Dict:
    """
    Convert ``audit_data`` (from ``_build_audit_data()``) into a SARIF 2.1.0 document.

    The function maps each finding in ``audit_data`` to one or more SARIF ``result``
    objects according to the following rule mapping:

    * ``SSC001`` — Known CVE (one result per CVE, CRITICAL/HIGH only)
    * ``SSC002`` — Malicious package (non-typosquat)
    * ``SSC003`` — Typo-squatting attack
    * ``SSC004`` — Suspicious AST IOC (one result per finding)
    * ``SSC005`` — Hardcoded credential / high-entropy secret
    * ``SSC006`` — Crypto wallet address embedded
    * ``SSC007`` — Outdated package (newer version available)
    * ``SSC008`` — Threat intelligence match (other sources)

    Args:
        audit_data: List of per-package audit dicts produced by
                    ``_build_audit_data()`` in ``monitor.py``.
        image_name: Docker image or container name being scanned; embedded in
                    ``automationDetails.id`` and the ``invocations`` command line.
        sbom_file:  Optional path to the SBOM JSON file (informational only;
                    not currently embedded in the SARIF output).

    Returns:
        A Python ``dict`` representing a complete SARIF 2.1.0 document ready
        to be serialised with ``json.dumps()``.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    results: List[Dict] = []
    fired_rule_ids: set = set()

    for entry in audit_data:
        pkg_name: str = entry.get("package", "unknown")
        ecosystem: str = entry.get("ecosystem", "unknown")
        version: str = entry.get("current_version", "unknown")
        latest: str = entry.get("latest_version", "N/A")
        severity: str = entry.get("severity", "NONE")
        cve_ids: List[str] = entry.get("cve_ids", []) or []
        cvss_score: float = entry.get("cvss_score", 0.0)
        is_malicious: bool = bool(entry.get("is_malicious", False))
        threat_sources: List[str] = entry.get("threat_sources", []) or []
        ioc_ast: List = entry.get("ioc_ast", []) or []
        ioc_entropy_secrets: List[str] = entry.get("ioc_entropy_secrets", []) or []
        ioc_wallets: List[str] = entry.get("ioc_wallets", []) or []

        # ── SSC001: Known CVE (CRITICAL or HIGH with CVEs present) ──────────
        if severity.upper() in ("CRITICAL", "HIGH") and cve_ids:
            level = "error"
            for cve_id in cve_ids:
                msg = (
                    f"Package {pkg_name}@{version} has known CVE {cve_id} "
                    f"with CVSS {cvss_score} ({severity})"
                )
                results.append(
                    _make_result("SSC001", level, msg, pkg_name, ecosystem, version, cve_id)
                )
                fired_rule_ids.add("SSC001")

        # ── SSC003 / SSC002: Malicious packages ─────────────────────────────
        if is_malicious:
            is_typosquat = any(
                "typo" in src.lower() or "typo-squatting" in src.lower()
                for src in threat_sources
            )
            if is_typosquat:
                msg = (
                    f"Package {pkg_name}@{version} appears to be a typo-squatting attack "
                    f"targeting a legitimate package. Threat source(s): "
                    f"{'; '.join(threat_sources)}"
                )
                results.append(
                    _make_result("SSC003", "error", msg, pkg_name, ecosystem, version, "typosquat")
                )
                fired_rule_ids.add("SSC003")
            else:
                src_text = "; ".join(threat_sources) if threat_sources else "Unknown"
                msg = (
                    f"Package {pkg_name}@{version} has been identified as malicious. "
                    f"Threat source(s): {src_text}"
                )
                results.append(
                    _make_result("SSC002", "error", msg, pkg_name, ecosystem, version, "malicious")
                )
                fired_rule_ids.add("SSC002")

        # ── SSC004: Suspicious AST IOCs ──────────────────────────────────────
        for ast_finding in ioc_ast:
            # ast_finding may be a dict or a string
            if isinstance(ast_finding, dict):
                raw_desc = (
                    ast_finding.get("description")
                    or ast_finding.get("message")
                    or str(ast_finding)
                )
                finding_key = ast_finding.get("node_type", raw_desc[:40])
            else:
                raw_desc = str(ast_finding)
                finding_key = raw_desc[:40]

            desc = raw_desc[:200] if len(raw_desc) > 200 else raw_desc
            msg = (
                f"Package {pkg_name}@{version} contains a suspicious AST pattern: {desc}"
            )
            results.append(
                _make_result("SSC004", "warning", msg, pkg_name, ecosystem, version, finding_key)
            )
            fired_rule_ids.add("SSC004")

        # ── SSC005: Hardcoded credentials / high-entropy secrets ─────────────
        for secret in ioc_entropy_secrets:
            truncated = secret[:80] + "..." if len(secret) > 80 else secret
            msg = (
                f"Package {pkg_name}@{version} contains a high-entropy secret or hardcoded "
                f"credential: {truncated}"
            )
            results.append(
                _make_result("SSC005", "error", msg, pkg_name, ecosystem, version, secret[:40])
            )
            fired_rule_ids.add("SSC005")

        # ── SSC006: Crypto wallet addresses ──────────────────────────────────
        for wallet in ioc_wallets:
            msg = (
                f"Package {pkg_name}@{version} contains an embedded cryptocurrency wallet "
                f"address: {wallet}"
            )
            results.append(
                _make_result("SSC006", "warning", msg, pkg_name, ecosystem, version, wallet[:40])
            )
            fired_rule_ids.add("SSC006")

        # ── SSC007: Outdated package ──────────────────────────────────────────
        if (
            latest
            and latest not in ("N/A", "")
            and latest != version
        ):
            msg = (
                f"Package {pkg_name}@{version} is outdated. Latest available version is "
                f"{latest}. Upgrade to receive security patches and bug fixes."
            )
            results.append(
                _make_result("SSC007", "note", msg, pkg_name, ecosystem, version, "outdated")
            )
            fired_rule_ids.add("SSC007")

        # ── SSC008: Other threat intelligence matches ─────────────────────────
        # Emit for threat_sources that are NOT typosquat (already covered by SSC003) and where
        # the package was not already flagged as generically malicious (SSC002), but still has
        # threat intel entries (e.g., GitHub Advisory without a MAL- prefix).
        other_sources = [
            src for src in threat_sources
            if not (
                "typo" in src.lower()
                or "typo-squatting" in src.lower()
            )
        ]
        if other_sources and not is_malicious:
            msg = (
                f"Package {pkg_name}@{version} matched threat intelligence source(s): "
                f"{'; '.join(other_sources)}"
            )
            results.append(
                _make_result(
                    "SSC008", "error", msg, pkg_name, ecosystem, version,
                    other_sources[0][:40]
                )
            )
            fired_rule_ids.add("SSC008")

    # ── Build rules list (only rules that fired, for compactness) ────────────
    # GitHub also accepts the full catalogue; we include only fired rules to
    # keep the file small and focused.
    rules = [_RULES_BY_ID[rid] for rid in sorted(fired_rule_ids)]
    # If nothing fired, include the full catalogue so GitHub can still import the run.
    if not rules:
        rules = [_RULES_BY_ID[rid] for (rid, *_) in _RULE_CATALOGUE]

    # ── versionControlProvenance (optional) ──────────────────────────────────
    script_dir = os.path.dirname(os.path.abspath(__file__))
    remote_url = _git_remote_url(script_dir)
    version_control = []
    if remote_url:
        version_control.append({"repositoryUri": remote_url})

    # ── Assemble the SARIF document ───────────────────────────────────────────
    sarif_doc: Dict = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Supply Chain Sentinel",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/vighnesh/supply-chain-sentinel",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"python monitor.py --image {image_name}",
                    }
                ],
                "automationDetails": {
                    "id": f"supply-chain-sentinel/{image_name}/{timestamp}",
                },
                "results": results,
                **({"versionControlProvenance": version_control} if version_control else {}),
            }
        ],
    }

    return sarif_doc


def export_sarif(
    audit_data: List[Dict],
    image_name: str,
    output_path: str,
    sbom_file: Optional[str] = None,
) -> Dict:
    """
    Generate a SARIF 2.1.0 document from ``audit_data`` and write it to disk.

    The output file is pretty-printed JSON with 2-space indentation, ready to
    be uploaded to GitHub Code Scanning.

    Args:
        audit_data:  List of per-package audit dicts (from ``_build_audit_data()``).
        image_name:  Docker image / container name being scanned.
        output_path: Absolute or relative path where the ``.sarif`` file will be
                     written.  Parent directories are created automatically.
        sbom_file:   Optional SBOM file path (forwarded to ``generate_sarif()``).

    Returns:
        The generated SARIF document as a Python ``dict`` (identical to what
        ``generate_sarif()`` returns, so callers can pass it straight to
        ``get_sarif_summary()``).
    """
    sarif_doc = generate_sarif(audit_data, image_name, sbom_file)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(sarif_doc, fh, indent=2, ensure_ascii=False)

    console.print(f"  [bold green][OK][/] SARIF report written to: {output_path}")
    return sarif_doc


def get_sarif_summary(sarif_doc: Dict) -> Dict:
    """
    Return a quick numeric summary of a SARIF document.

    Extracts result counts by level and lists the distinct rule IDs that
    produced at least one result, plus the set of packages that received an
    ``"error"``-level finding (useful for dashboards and CI gates).

    Args:
        sarif_doc: A SARIF 2.1.0 document dict as returned by ``generate_sarif()``
                   or ``export_sarif()``.

    Returns:
        A dict with the following keys:

        * ``total_results`` (int): Total number of results across all runs.
        * ``errors`` (int): Number of results with level ``"error"``.
        * ``warnings`` (int): Number of results with level ``"warning"``.
        * ``notes`` (int): Number of results with level ``"note"``.
        * ``rules_fired`` (list[str]): Sorted list of distinct rule IDs that
          produced at least one result.
        * ``critical_packages`` (list[str]): Sorted list of
          ``"ecosystem/package@version"`` strings for packages with at least
          one ``"error"``-level result.
    """
    errors = 0
    warnings = 0
    notes = 0
    rules_fired: set = set()
    critical_fqns: set = set()

    for run in sarif_doc.get("runs", []):
        for result in run.get("results", []):
            level = result.get("level", "warning")
            rule_id = result.get("ruleId", "")
            if level == "error":
                errors += 1
                # Collect fully-qualified package name from logical location
                for loc in result.get("locations", []):
                    for ll in loc.get("logicalLocations", []):
                        fqn = ll.get("fullyQualifiedName", ll.get("name", ""))
                        if fqn:
                            critical_fqns.add(fqn)
            elif level == "warning":
                warnings += 1
            else:
                notes += 1
            if rule_id:
                rules_fired.add(rule_id)

    return {
        "total_results": errors + warnings + notes,
        "errors": errors,
        "warnings": warnings,
        "notes": notes,
        "rules_fired": sorted(rules_fired),
        "critical_packages": sorted(critical_fqns),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Demo / smoke-test
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _MOCK_AUDIT_DATA = [
        {
            "package": "requests",
            "ecosystem": "PyPI",
            "current_version": "2.25.0",
            "latest_version": "2.31.0",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "cve_ids": ["CVE-2023-32681"],
            "vuln_count": 1,
            "is_malicious": False,
            "threat_sources": [],
            "ioc_ast": [],
            "ioc_wallets": [],
            "ioc_entropy_secrets": [],
        },
        {
            "package": "colourama",  # well-known typosquat of 'colorama'
            "ecosystem": "PyPI",
            "current_version": "0.3.3",
            "latest_version": "0.3.3",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cve_ids": [],
            "vuln_count": 0,
            "is_malicious": True,
            "threat_sources": ["Typo-squatting: colorama"],
            "ioc_ast": [
                {
                    "node_type": "Call",
                    "description": "Dynamic exec() call with base64-encoded payload detected",
                }
            ],
            "ioc_wallets": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf?Na"],
            "ioc_entropy_secrets": ["AKIAIOSFODNN7EXAMPLE"],
        },
        {
            "package": "lodash",
            "ecosystem": "npm",
            "current_version": "4.17.11",
            "latest_version": "4.17.21",
            "severity": "LOW",
            "cvss_score": 3.1,
            "cve_ids": [],
            "vuln_count": 0,
            "is_malicious": False,
            "threat_sources": ["GitHub Advisory: GHSA-p6mc-m468-83gw"],
            "ioc_ast": [],
            "ioc_wallets": [],
            "ioc_entropy_secrets": [],
        },
        {
            "package": "safe-package",
            "ecosystem": "PyPI",
            "current_version": "1.0.0",
            "latest_version": "1.0.0",
            "severity": "NONE",
            "cvss_score": 0.0,
            "cve_ids": [],
            "vuln_count": 0,
            "is_malicious": False,
            "threat_sources": [],
            "ioc_ast": [],
            "ioc_wallets": [],
            "ioc_entropy_secrets": [],
        },
    ]

    console.print("\n[bold cyan]Supply Chain Sentinel — SARIF Exporter Demo[/]\n")
    console.print("[dim]Generating SARIF from mock audit data...[/]")

    _doc = generate_sarif(_MOCK_AUDIT_DATA, "demo-image:latest")
    _summary = get_sarif_summary(_doc)

    console.print(f"\n[bold]SARIF Summary:[/]")
    console.print(f"  Total results : {_summary['total_results']}")
    console.print(f"  Errors        : [bold red]{_summary['errors']}[/]")
    console.print(f"  Warnings      : [bold yellow]{_summary['warnings']}[/]")
    console.print(f"  Notes         : [dim]{_summary['notes']}[/]")
    console.print(f"  Rules fired   : {', '.join(_summary['rules_fired'])}")
    console.print(f"  Critical pkgs : {', '.join(_summary['critical_packages'])}")

    import tempfile, pathlib
    _out = pathlib.Path(tempfile.gettempdir()) / "demo_supply_chain_sentinel.sarif"
    export_sarif(_MOCK_AUDIT_DATA, "demo-image:latest", str(_out))
    console.print(f"\n[dim]Full SARIF written to: {_out}[/]")
