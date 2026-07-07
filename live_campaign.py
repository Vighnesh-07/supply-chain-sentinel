
#!/usr/bin/env python3

import re
import sys
import csv
from pathlib import Path

import requests


def parse_package_versions(path):
    """
    Parse lines like:
        "zapier-platform-schema": {"18.0.4", "18.0.3", "18.0.2"},
    into:
        {
          'zapier-platform-schema': {'18.0.4', '18.0.3', '18.0.2'},
          ...
        }
    """
    pkg_versions = {}
    # "name": {"v1", "v2", ...}
    pattern = re.compile(r'"([^"]+)"\s*:\s*\{([^}]*)\}')

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            m = pattern.search(line)
            if not m:
                continue

            pkg_name = m.group(1)
            versions_str = m.group(2)

            versions = []
            for part in versions_str.split(","):
                v = part.strip()
                if not v:
                    continue
                # Trim quotes
                if v.startswith('"') and v.endswith('"'):
                    v = v[1:-1]
                v = v.strip()
                if v:
                    versions.append(v)

            if versions:
                pkg_versions.setdefault(pkg_name, set()).update(versions)

    return pkg_versions


def fetch_npm_versions(npm_name):
    """
    Query npm for a package and return the set of versions.

    npm_name should be the real npm name, e.g.:
      - 'zapier-platform-schema'
      - '@crowdstrike/commitlint'
    """
    url = f"https://registry.npmjs.org/{npm_name}"
    try:
        resp = requests.get(url, timeout=15)
    except requests.RequestException as e:
        return None, f"request_error: {e}"

    if resp.status_code == 404:
        return None, "package_not_found"

    if not resp.ok:
        return None, f"http_error_{resp.status_code}"

    try:
        data = resp.json()
    except ValueError as e:
        return None, f"json_error: {e}"

    versions = set((data.get("versions") or {}).keys())
    return versions, "ok"


def check_versions(pkg_map, output_csv):
    """
    pkg_map: dict { display_name -> {versions} }
    output_csv: Path for CSV results
    """
    with open(output_csv, "w", encoding="utf-8", newline="") as f_out:
        writer = csv.writer(f_out)
        writer.writerow(["display_name", "npm_name", "version", "status", "note"])

        total = 0
        missing = 0

        for display_name, versions in sorted(pkg_map.items()):
            # Convert %40 to @ for scoped packages
            npm_name = display_name.replace("%40", "@")

            avail_versions, note = fetch_npm_versions(npm_name)

            if avail_versions is None:
                # Something went wrong (package missing / request error)
                for v in sorted(versions):
                    status = "missing" if note == "package_not_found" else "unknown"
                    writer.writerow([display_name, npm_name, v, status, note])
                    total += 1
                    if status == "missing":
                        missing += 1
                print(f"[!] {display_name} -> {note}")
                continue

            # Compare requested versions vs available
            for v in sorted(versions):
                if v in avail_versions:
                    status = "exists"
                else:
                    status = "missing"
                    missing += 1
                writer.writerow([display_name, npm_name, v, status, note])
                total += 1

            print(f"[+] {display_name} -> checked {len(versions)} version(s)")

    print()
    print(f"[=] Done. Checked {total} versions.")
    print(f"    Missing / not on npm: {missing}")
    print(f"    Results written to: {output_csv}")


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"Usage: {sys.argv[0]} input.txt [output.csv]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"[!] Input file not found: {input_path}")
        sys.exit(1)

    if len(sys.argv) == 3:
        output_csv = Path(sys.argv[2])
    else:
        output_csv = input_path.with_suffix(".csv")

    pkg_map = parse_package_versions(input_path)
    if not pkg_map:
        print("[!] No packages parsed from input file.")
        sys.exit(1)

    check_versions(pkg_map, output_csv)


if __name__ == "__main__":
    main()