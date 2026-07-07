"""
Supply Chain Sentinel — Runtime Container Scanner (Multi-Ecosystem)
=====================================================================
Connects to running Docker containers to extract active packages
across all supported language runtimes in real-time.

Supports: Python, Node.js, Go, Ruby, PHP, .NET, Rust, OS packages.
"""

import json
import subprocess
import re
from typing import List, Dict, Optional, Set
from rich.console import Console

console = Console()


# ═══════════════════════════════════════════════════════════════
# RUNTIME PROBING
# ═══════════════════════════════════════════════════════════════

def _exec_in_container(container_name: str, command: List[str], timeout: int = 15) -> Optional[str]:
    """Run a command inside a Docker container and return stdout, or None on failure."""
    try:
        cmd = ["docker", "exec", container_name] + command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    return None


def _probe_runtime(container_name: str, probe_commands: List[List[str]]) -> bool:
    """Check if a runtime exists in the container by running probe commands."""
    for cmd in probe_commands:
        output = _exec_in_container(container_name, cmd, timeout=5)
        if output is not None:
            return True
    return False


def probe_container_runtimes(container_name: str, include_os: bool = False) -> List[str]:
    """
    Detect which language runtimes are available inside a container.

    Returns:
        List of detected ecosystem names (e.g., ['PyPI', 'npm']).
    """
    detected = []

    # Python
    if _probe_runtime(container_name, [["python", "--version"], ["python3", "--version"]]):
        detected.append("PyPI")

    # Node.js
    if _probe_runtime(container_name, [["node", "--version"]]):
        detected.append("npm")

    # Ruby
    if _probe_runtime(container_name, [["ruby", "--version"]]):
        detected.append("RubyGems")

    # Go (less common in containers, but check)
    if _probe_runtime(container_name, [["go", "version"]]):
        detected.append("Go")

    # PHP
    if _probe_runtime(container_name, [["php", "--version"]]):
        detected.append("Packagist")

    # .NET
    if _probe_runtime(container_name, [["dotnet", "--version"]]):
        detected.append("NuGet")

    # Rust
    if _probe_runtime(container_name, [["rustc", "--version"]]):
        detected.append("crates.io")

    # OS package managers (opt-in)
    if include_os:
        if _probe_runtime(container_name, [["dpkg", "--version"]]):
            detected.append("Debian")
        elif _probe_runtime(container_name, [["apk", "--version"]]):
            detected.append("Alpine")
        elif _probe_runtime(container_name, [["rpm", "--version"]]):
            detected.append("RHEL")

    return detected


# ═══════════════════════════════════════════════════════════════
# PER-ECOSYSTEM EXTRACTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def _extract_python(container_name: str) -> List[Dict]:
    """Extract Python packages via pip or importlib.metadata fallback."""
    packages = []

    # Attempt 1: pip list
    output = _exec_in_container(container_name, ["pip", "list", "--format=json"])
    pip_data = None
    if output:
        try:
            pip_data = json.loads(output)
        except json.JSONDecodeError:
            pass

    # Attempt 2: pip3 list
    if pip_data is None:
        output = _exec_in_container(container_name, ["pip3", "list", "--format=json"])
        if output:
            try:
                pip_data = json.loads(output)
            except json.JSONDecodeError:
                pass

    # Attempt 3: importlib.metadata (native Python fallback)
    if pip_data is None:
        py_script = (
            "import json, importlib.metadata; "
            "print(json.dumps([{'name': d.metadata['Name'], 'version': d.version} "
            "for d in importlib.metadata.distributions() if d.metadata.get('Name')]))"
        )
        for py_bin in ["python", "python3"]:
            output = _exec_in_container(container_name, [py_bin, "-c", py_script])
            if output:
                try:
                    pip_data = json.loads(output)
                    break
                except json.JSONDecodeError:
                    continue

    if pip_data:
        for item in pip_data:
            name = item.get("name", "")
            version = item.get("version", "unknown")
            if name:
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": f"pkg:pypi/{name}@{version}",
                    "type": "library",
                    "ecosystem": "PyPI",
                })

    return packages


def _extract_npm(container_name: str) -> List[Dict]:
    """Extract Node.js packages via npm list or package.json."""
    packages = []

    # Attempt 1: npm list --json
    output = _exec_in_container(container_name, ["npm", "list", "--json", "--all", "--depth=0"])
    if output:
        try:
            data = json.loads(output)
            deps = data.get("dependencies", {})
            for name, info in deps.items():
                version = info.get("version", "unknown") if isinstance(info, dict) else "unknown"
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": f"pkg:npm/{name}@{version}",
                    "type": "library",
                    "ecosystem": "npm",
                })
            return packages
        except json.JSONDecodeError:
            pass

    # Attempt 2: Read package.json from common locations
    for pkg_path in ["/app/package.json", "/usr/src/app/package.json", "/home/node/app/package.json"]:
        output = _exec_in_container(container_name, ["cat", pkg_path])
        if output:
            try:
                data = json.loads(output)
                all_deps = {}
                all_deps.update(data.get("dependencies", {}))
                all_deps.update(data.get("devDependencies", {}))
                for name, version_spec in all_deps.items():
                    # Strip semver prefixes (^, ~, >=, etc.)
                    version = re.sub(r'^[\^~>=<]*', '', version_spec)
                    packages.append({
                        "name": name,
                        "version": version,
                        "purl": f"pkg:npm/{name}@{version}",
                        "type": "library",
                        "ecosystem": "npm",
                    })
                return packages
            except json.JSONDecodeError:
                continue

    return packages


def _extract_ruby(container_name: str) -> List[Dict]:
    """Extract Ruby gems via gem list."""
    packages = []
    output = _exec_in_container(container_name, ["gem", "list", "--local", "--no-details"])
    if output:
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: "gem_name (version1, version2)"
            match = re.match(r'^(\S+)\s+\((.+)\)$', line)
            if match:
                name = match.group(1)
                versions = match.group(2).split(",")
                version = versions[0].strip()  # Use the first (latest) version
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": f"pkg:gem/{name}@{version}",
                    "type": "library",
                    "ecosystem": "RubyGems",
                })
    return packages


def _extract_go(container_name: str) -> List[Dict]:
    """Extract Go modules via go list."""
    packages = []
    output = _exec_in_container(container_name, ["go", "list", "-m", "-json", "all"], timeout=30)
    if output:
        # go list -m -json outputs concatenated JSON objects (not an array)
        decoder = json.JSONDecoder()
        pos = 0
        while pos < len(output):
            try:
                # Skip whitespace
                while pos < len(output) and output[pos] in ' \t\n\r':
                    pos += 1
                if pos >= len(output):
                    break
                obj, end_pos = decoder.raw_decode(output, pos)
                pos = end_pos
                name = obj.get("Path", "")
                version = obj.get("Version", "").lstrip("v")
                if name and version and not obj.get("Main"):
                    packages.append({
                        "name": name,
                        "version": version,
                        "purl": f"pkg:golang/{name}@{version}",
                        "type": "library",
                        "ecosystem": "Go",
                    })
            except json.JSONDecodeError:
                break
    return packages


def _extract_php(container_name: str) -> List[Dict]:
    """Extract PHP packages via composer show."""
    packages = []
    output = _exec_in_container(container_name, ["composer", "show", "--format=json", "--no-ansi"], timeout=30)
    if output:
        try:
            data = json.loads(output)
            for item in data.get("installed", []):
                name = item.get("name", "")
                version = item.get("version", "unknown").lstrip("v")
                if name:
                    packages.append({
                        "name": name,
                        "version": version,
                        "purl": f"pkg:composer/{name}@{version}",
                        "type": "library",
                        "ecosystem": "Packagist",
                    })
        except json.JSONDecodeError:
            pass
    return packages


def _extract_dotnet(container_name: str) -> List[Dict]:
    """Extract .NET packages via dotnet list package."""
    packages = []
    output = _exec_in_container(container_name, ["dotnet", "list", "package", "--format", "json"], timeout=30)
    if output:
        try:
            data = json.loads(output)
            for project in data.get("projects", []):
                for framework in project.get("frameworks", []):
                    for pkg in framework.get("topLevelPackages", []):
                        name = pkg.get("id", "")
                        version = pkg.get("resolvedVersion", "unknown")
                        if name:
                            packages.append({
                                "name": name,
                                "version": version,
                                "purl": f"pkg:nuget/{name}@{version}",
                                "type": "library",
                                "ecosystem": "NuGet",
                            })
        except json.JSONDecodeError:
            pass
    return packages


def _extract_rust(container_name: str) -> List[Dict]:
    """Extract Rust crates via cargo metadata."""
    packages = []
    output = _exec_in_container(container_name, ["cargo", "metadata", "--format-version", "1", "--no-deps"], timeout=30)
    if output:
        try:
            data = json.loads(output)
            for pkg in data.get("packages", []):
                name = pkg.get("name", "")
                version = pkg.get("version", "unknown")
                if name:
                    packages.append({
                        "name": name,
                        "version": version,
                        "purl": f"pkg:cargo/{name}@{version}",
                        "type": "library",
                        "ecosystem": "crates.io",
                    })
        except json.JSONDecodeError:
            pass
    return packages


def _extract_os_debian(container_name: str) -> List[Dict]:
    """Extract Debian/Ubuntu packages via dpkg-query."""
    packages = []
    output = _exec_in_container(container_name, [
        "dpkg-query", "-W", "-f", "${Package}\t${Version}\n"
    ])
    if output:
        for line in output.splitlines():
            parts = line.strip().split("\t")
            if len(parts) == 2:
                name, version = parts
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": f"pkg:deb/debian/{name}@{version}",
                    "type": "library",
                    "ecosystem": "Debian",
                })
    return packages


def _extract_os_alpine(container_name: str) -> List[Dict]:
    """Extract Alpine packages via apk info."""
    packages = []
    output = _exec_in_container(container_name, ["apk", "info", "-v"])
    if output:
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: "package-name-1.2.3-r0"
            # Split on last two hyphens for version
            match = re.match(r'^(.+)-(\d+\..+)$', line)
            if match:
                name = match.group(1)
                version = match.group(2)
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": f"pkg:apk/alpine/{name}@{version}",
                    "type": "library",
                    "ecosystem": "Alpine",
                })
    return packages


def _extract_os_rpm(container_name: str) -> List[Dict]:
    """Extract RPM packages via rpm -qa."""
    packages = []
    output = _exec_in_container(container_name, [
        "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"
    ])
    if output:
        for line in output.splitlines():
            parts = line.strip().split("\t")
            if len(parts) == 2:
                name, version = parts
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": f"pkg:rpm/{name}@{version}",
                    "type": "library",
                    "ecosystem": "RHEL",
                })
    return packages


# ═══════════════════════════════════════════════════════════════
# EXTRACTION ROUTER
# ═══════════════════════════════════════════════════════════════

_EXTRACTORS = {
    "PyPI": _extract_python,
    "npm": _extract_npm,
    "RubyGems": _extract_ruby,
    "Go": _extract_go,
    "Packagist": _extract_php,
    "NuGet": _extract_dotnet,
    "crates.io": _extract_rust,
    "Debian": _extract_os_debian,
    "Alpine": _extract_os_alpine,
    "RHEL": _extract_os_rpm,
}


# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

def get_live_packages(container_name: str, include_os: bool = False) -> List[Dict]:
    """
    Extract all active packages from a running container across all detected runtimes.

    Args:
        container_name: Name or ID of the running Docker container.
        include_os: If True, also scan OS-level packages (dpkg, apk, rpm).

    Returns:
        List of dicts with keys: name, version, purl, type, ecosystem.
        Returns empty list if container is not running or no packages found.
    """
    # Step 1: Probe which runtimes exist
    detected = probe_container_runtimes(container_name, include_os=include_os)

    if not detected:
        return []

    eco_display = ", ".join(detected)
    console.print(f"  [bold green][OK][/] Detected ecosystems in '{container_name}': [bold magenta]{eco_display}[/]")

    # Step 2: Extract packages from each detected runtime
    all_packages = []
    for eco_name in detected:
        extractor = _EXTRACTORS.get(eco_name)
        if extractor:
            try:
                pkgs = extractor(container_name)
                if pkgs:
                    console.print(f"  [dim]  -> {eco_name}: {len(pkgs)} packages extracted[/]")
                    all_packages.extend(pkgs)
                else:
                    console.print(f"  [dim]  -> {eco_name}: runtime detected but no packages found[/]")
            except Exception:
                console.print(f"  [dim yellow]  -> {eco_name}: extraction failed (skipping)[/]")

    # Deduplicate by (name, version, ecosystem)
    seen: Set = set()
    unique_packages = []
    for pkg in all_packages:
        key = (pkg["name"].lower(), pkg["version"], pkg["ecosystem"])
        if key not in seen:
            seen.add(key)
            unique_packages.append(pkg)

    return unique_packages


def get_all_running_containers() -> List[str]:
    """
    Get a list of all currently running Docker container names.
    """
    cmd = ["docker", "ps", "--format", "{{.Names}}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return []
        # Filter out empty strings
        return [name.strip() for name in result.stdout.splitlines() if name.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
