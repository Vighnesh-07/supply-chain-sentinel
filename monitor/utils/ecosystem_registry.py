"""
Supply Chain Sentinel — Ecosystem Registry
=============================================
Centralized configuration mapping each supported programming language
ecosystem to its package manager, registry API, PURL prefix, and
docker exec extraction commands.

Supports: Python, Node.js, Go, Ruby, Java, Rust, PHP, .NET, OS packages
"""

from typing import Dict, List, Optional

# ═══════════════════════════════════════════════════════════════
# ECOSYSTEM DEFINITIONS
# ═══════════════════════════════════════════════════════════════

ECOSYSTEMS: Dict[str, Dict] = {
    # ── Python (PyPI) ──
    "PyPI": {
        "display_name": "Python (PyPI)",
        "purl_types": ["pypi"],
        "osv_ecosystem": "PyPI",
        "registry_url": "https://pypi.org/pypi/{name}/json",
        "registry_version_path": ["info", "version"],
        "docker_exec_commands": [
            {
                "label": "pip list",
                "command": ["pip", "list", "--format=json"],
                "parser": "json_list",
            },
            {
                "label": "pip3 list",
                "command": ["pip3", "list", "--format=json"],
                "parser": "json_list",
            },
            {
                "label": "importlib.metadata (native)",
                "command_template": "python_importlib",
                "parser": "json_list",
            },
        ],
        "probe_commands": [
            ["python", "--version"],
            ["python3", "--version"],
        ],
    },

    # ── Node.js (npm) ──
    "npm": {
        "display_name": "Node.js (npm)",
        "purl_types": ["npm"],
        "osv_ecosystem": "npm",
        "registry_url": "https://registry.npmjs.org/{name}",
        "registry_version_path": ["dist-tags", "latest"],
        "docker_exec_commands": [
            {
                "label": "npm list",
                "command": ["npm", "list", "--json", "--all", "--depth=0"],
                "parser": "npm_json",
            },
            {
                "label": "package.json read",
                "command_template": "node_package_json",
                "parser": "package_json",
            },
        ],
        "probe_commands": [
            ["node", "--version"],
        ],
    },

    # ── Go ──
    "Go": {
        "display_name": "Go",
        "purl_types": ["golang"],
        "osv_ecosystem": "Go",
        "registry_url": "https://proxy.golang.org/{name}/@latest",
        "registry_version_path": ["Version"],
        "docker_exec_commands": [
            {
                "label": "go list modules",
                "command": ["go", "list", "-m", "-json", "all"],
                "parser": "go_modules",
            },
        ],
        "probe_commands": [
            ["go", "version"],
        ],
    },

    # ── Ruby (RubyGems) ──
    "RubyGems": {
        "display_name": "Ruby (RubyGems)",
        "purl_types": ["gem"],
        "osv_ecosystem": "RubyGems",
        "registry_url": "https://rubygems.org/api/v1/gems/{name}.json",
        "registry_version_path": ["version"],
        "docker_exec_commands": [
            {
                "label": "gem list",
                "command": ["gem", "list", "--local", "--no-details"],
                "parser": "gem_list",
            },
        ],
        "probe_commands": [
            ["ruby", "--version"],
        ],
    },

    # ── Java (Maven) ──
    "Maven": {
        "display_name": "Java (Maven)",
        "purl_types": ["maven"],
        "osv_ecosystem": "Maven",
        "registry_url": "https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}&rows=1&wt=json",
        "registry_version_path": ["response", "docs", 0, "latestVersion"],
        "docker_exec_commands": [
            {
                "label": "JAR listing",
                "command_template": "java_jar_scan",
                "parser": "jar_list",
            },
        ],
        "probe_commands": [
            ["java", "-version"],
        ],
    },

    # ── Rust (crates.io) ──
    "crates.io": {
        "display_name": "Rust (crates.io)",
        "purl_types": ["cargo"],
        "osv_ecosystem": "crates.io",
        "registry_url": "https://crates.io/api/v1/crates/{name}",
        "registry_version_path": ["crate", "max_stable_version"],
        "docker_exec_commands": [
            {
                "label": "cargo metadata",
                "command": ["cargo", "metadata", "--format-version", "1", "--no-deps"],
                "parser": "cargo_metadata",
            },
        ],
        "probe_commands": [
            ["rustc", "--version"],
        ],
    },

    # ── PHP (Composer / Packagist) ──
    "Packagist": {
        "display_name": "PHP (Packagist)",
        "purl_types": ["composer"],
        "osv_ecosystem": "Packagist",
        "registry_url": "https://repo.packagist.org/p2/{name}.json",
        "registry_version_path": None,  # Requires custom parsing
        "docker_exec_commands": [
            {
                "label": "composer show",
                "command": ["composer", "show", "--format=json", "--no-ansi"],
                "parser": "composer_json",
            },
        ],
        "probe_commands": [
            ["php", "--version"],
        ],
    },

    # ── .NET (NuGet) ──
    "NuGet": {
        "display_name": ".NET (NuGet)",
        "purl_types": ["nuget"],
        "osv_ecosystem": "NuGet",
        "registry_url": "https://api.nuget.org/v3-flatcontainer/{name}/index.json",
        "registry_version_path": None,  # Last item in "versions" array
        "docker_exec_commands": [
            {
                "label": "dotnet list package",
                "command": ["dotnet", "list", "package", "--format", "json"],
                "parser": "dotnet_json",
            },
        ],
        "probe_commands": [
            ["dotnet", "--version"],
        ],
    },
}

# ═══════════════════════════════════════════════════════════════
# OS-LEVEL PACKAGE MANAGERS (opt-in via --include-os)
# ═══════════════════════════════════════════════════════════════

OS_ECOSYSTEMS: Dict[str, Dict] = {
    "Debian": {
        "display_name": "Debian/Ubuntu (dpkg)",
        "purl_types": ["deb"],
        "osv_ecosystem": "Debian",
        "docker_exec_commands": [
            {
                "label": "dpkg-query",
                "command": ["dpkg-query", "-W", "-f", "${Package}\\t${Version}\\n"],
                "parser": "tsv_list",
            },
        ],
        "probe_commands": [
            ["dpkg", "--version"],
        ],
    },
    "Alpine": {
        "display_name": "Alpine (apk)",
        "purl_types": ["apk"],
        "osv_ecosystem": "Alpine",
        "docker_exec_commands": [
            {
                "label": "apk info",
                "command": ["apk", "info", "-v"],
                "parser": "apk_list",
            },
        ],
        "probe_commands": [
            ["apk", "--version"],
        ],
    },
    "RHEL": {
        "display_name": "RHEL/CentOS (rpm)",
        "purl_types": ["rpm"],
        "osv_ecosystem": "Linux",
        "docker_exec_commands": [
            {
                "label": "rpm -qa",
                "command": ["rpm", "-qa", "--queryformat", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"],
                "parser": "tsv_list",
            },
        ],
        "probe_commands": [
            ["rpm", "--version"],
        ],
    },
}


# ═══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def get_all_ecosystems(include_os: bool = False) -> Dict[str, Dict]:
    """Return all ecosystem definitions, optionally including OS packages."""
    result = dict(ECOSYSTEMS)
    if include_os:
        result.update(OS_ECOSYSTEMS)
    return result


def get_ecosystem_by_purl(purl: str, include_os: bool = False) -> Optional[str]:
    """
    Determine the ecosystem name from a PURL string.

    Args:
        purl: Package URL (e.g., 'pkg:pypi/requests@2.31.0')
        include_os: Whether to check OS ecosystems too.

    Returns:
        Ecosystem name (e.g., 'PyPI', 'npm') or None if unrecognized.
    """
    purl_lower = purl.lower()
    all_eco = get_all_ecosystems(include_os)

    for eco_name, eco_config in all_eco.items():
        for purl_type in eco_config["purl_types"]:
            if f"pkg:{purl_type}/" in purl_lower:
                return eco_name

    return None


def get_osv_ecosystem(ecosystem_name: str) -> str:
    """
    Get the OSV-compatible ecosystem identifier for a given ecosystem.

    Args:
        ecosystem_name: Our internal ecosystem name (e.g., 'PyPI', 'npm')

    Returns:
        OSV ecosystem string.
    """
    all_eco = get_all_ecosystems(include_os=True)
    eco_config = all_eco.get(ecosystem_name, {})
    return eco_config.get("osv_ecosystem", ecosystem_name)


# ═══════════════════════════════════════════════════════════════
# PURL PREFIX → ECOSYSTEM QUICK LOOKUP TABLE
# ═══════════════════════════════════════════════════════════════

PURL_TO_ECOSYSTEM = {}
for _eco_name, _eco_cfg in get_all_ecosystems(include_os=True).items():
    for _pt in _eco_cfg["purl_types"]:
        PURL_TO_ECOSYSTEM[_pt] = _eco_name
