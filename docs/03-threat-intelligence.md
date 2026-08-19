# Multi-Database Threat Intelligence Engine

> How Supply Chain Sentinel cross-references packages against four independent threat databases to detect known-malicious, advisory-flagged, and typosquatted dependencies.

[![Back to README](https://img.shields.io/badge/Back_to-README-blue?style=flat-square)](../README.md)
[![System Overview](https://img.shields.io/badge/See-System_Overview-lightgrey?style=flat-square)](./01-system-overview.md)

---

## Architecture Diagram

```mermaid
flowchart TD
    subgraph INPUT["PACKAGE LIST"]
        PKG["Parsed SBOM Components\nname + version + ecosystem"]
    end

    subgraph PARALLEL["PARALLEL THREAT CHECKS"]
        direction LR
        subgraph MAL["CHECK 1: OSV MAL-"]
            M1["Query OSV API\nfilter: id prefix MAL-"]
            M2{"MAL- match\nfound?"}
            M3["Flag: MALICIOUS\nSource: OSV MAL-"]
            M1 --> M2
            M2 -- "Yes" --> M3
        end

        subgraph GHSA["CHECK 2: GITHUB ADVISORY"]
            G1["Query GitHub Advisory DB\nGHSA- prefixed IDs"]
            G2{"GHSA match\nfound?"}
            G3["Flag: ADVISORY\nSource: GHSA"]
            G1 --> G2
            G2 -- "Yes" --> G3
        end

        subgraph BLOCK["CHECK 3: LOCAL BLOCKLIST"]
            B1["Lookup in\nknown_malicious.json"]
            B2{"Exact name +\nversion match?"}
            B3["Flag: MALICIOUS\nSource: Blocklist"]
            B1 --> B2
            B2 -- "Yes" --> B3
        end

        subgraph TYPO["CHECK 4: TYPOSQUAT DETECTOR"]
            T1["Load Popular Package\nCorpus per Ecosystem"]
            T2["Compute Levenshtein\nDistance to each"]
            T3{"Distance <= 2\nAND name not\nin corpus?"}
            T4["Flag: SUSPICIOUS\nSource: Typosquat"]
            T1 --> T2 --> T3
            T3 -- "Yes" --> T4
        end
    end

    subgraph DECISION["DECISION ENGINE"]
        DE1{"Any source\nflagged\nMALICIOUS?"}
        DE2["Verdict:\nMALICIOUS"]
        DE3{"Any source\nflagged\nADVISORY or\nSUSPICIOUS?"}
        DE4["Verdict:\nADVISORY"]
        DE5["Verdict:\nCLEAN"]

        DE1 -- "Yes" --> DE2
        DE1 -- "No" --> DE3
        DE3 -- "Yes" --> DE4
        DE3 -- "No" --> DE5
    end

    subgraph OUTPUT["THREAT INTELLIGENCE REPORT"]
        RPT["Per-Package Findings\nVerdict | Source | Evidence"]
    end

    PKG --> M1 & G1 & B1 & T1
    M2 -- "No" --> DE1
    G2 -- "No" --> DE1
    B2 -- "No" --> DE1
    T3 -- "No" --> DE1
    M3 --> DE1
    G3 --> DE1
    B3 --> DE1
    T4 --> DE1
    DE2 --> RPT
    DE4 --> RPT
    DE5 --> RPT

    classDef inputStyle fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#eee
    classDef malStyle fill:#3b0a0a,stroke:#e74c3c,stroke-width:2px,color:#eee
    classDef ghsaStyle fill:#2c1a3b,stroke:#9b59b6,stroke-width:2px,color:#eee
    classDef blockStyle fill:#3b2a0a,stroke:#e67e22,stroke-width:2px,color:#eee
    classDef typoStyle fill:#0a2a3b,stroke:#3498db,stroke-width:2px,color:#eee
    classDef decisionStyle fill:#1a2a1a,stroke:#f1c40f,stroke-width:2px,color:#eee
    classDef outputStyle fill:#0d3b0d,stroke:#2ecc71,stroke-width:2px,color:#eee

    class PKG inputStyle
    class M1,M2,M3 malStyle
    class G1,G2,G3 ghsaStyle
    class B1,B2,B3 blockStyle
    class T1,T2,T3,T4 typoStyle
    class DE1,DE2,DE3,DE4,DE5 decisionStyle
    class RPT outputStyle
```

---

## Threat Database Details

### Check 1: OSV MAL- Advisories

The [OSV.dev](https://osv.dev) database maintains a dedicated class of advisories with the `MAL-` prefix. These are sourced from the [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) repository and represent **confirmed malicious packages** identified by the open-source security community.

| Property | Detail |
|----------|--------|
| **Data Source** | OSV.dev + OpenSSF Malicious Packages |
| **ID Format** | `MAL-YYYY-NNNN` |
| **Query Method** | `POST /v1/query` with package name/version; filter response IDs starting with `MAL-` |
| **Signal Strength** | Definitive -- confirmed malicious by maintainers |
| **Coverage** | PyPI, npm, RubyGems, crates.io, NuGet, Go |

### Check 2: GitHub Advisory Database (GHSA)

The GitHub Advisory Database aggregates security advisories from multiple sources including NVD, package maintainers, and community reports. Advisories with the `GHSA-` prefix may indicate vulnerabilities that are **actively exploited** or have known malware associations.

| Property | Detail |
|----------|--------|
| **Data Source** | GitHub Advisory Database |
| **ID Format** | `GHSA-xxxx-xxxx-xxxx` |
| **Query Method** | Via OSV API (GHSA IDs are cross-listed) or GitHub GraphQL API |
| **Signal Strength** | High -- reviewed by GitHub security team |
| **Coverage** | All major ecosystems supported by GitHub |

### Check 3: Local Blocklist

A curated JSON file (`known_malicious.json`) containing packages confirmed malicious through incident response, blog posts, and security research. This list is manually maintained and updated with each release.

| Property | Detail |
|----------|--------|
| **Data Source** | Curated from security research, ReversingLabs, Phylum, Snyk blogs |
| **Format** | JSON map: `ecosystem -> [{ name, version, reason, reference_url }]` |
| **Query Method** | Exact match on `(ecosystem, name, version)` tuple |
| **Signal Strength** | Definitive -- manually verified entries |
| **Update Cadence** | With each Sentinel release; pull requests accepted |

### Check 4: Typosquat Detection

Typosquatting is a technique where attackers publish packages with names deliberately similar to popular legitimate packages (e.g., `requets` instead of `requests`). The detector computes the **Levenshtein edit distance** between each SBOM package name and a corpus of the top 5,000 packages per ecosystem.

| Property | Detail |
|----------|--------|
| **Algorithm** | Levenshtein (edit) distance |
| **Threshold** | Distance <= 2 AND the package name is NOT itself in the popular corpus |
| **Corpus Source** | Top 5,000 packages by weekly downloads per ecosystem |
| **Signal Strength** | Heuristic -- requires human or AI verification |
| **False Positive Rate** | Moderate; mitigated by the AI intent analysis in Stage 5 |

---

## Detection Techniques Summary

| Technique | Detects | Confidence | False Positive Risk |
|-----------|---------|------------|---------------------|
| OSV MAL- lookup | Confirmed malware packages | Very High | Very Low |
| GHSA cross-reference | Packages with known security advisories | High | Low |
| Blocklist exact match | Previously reported malware | Very High | None |
| Levenshtein typosquat | Name-confusion attacks | Medium | Moderate |

---

## Decision Logic

The decision engine applies a **priority cascade** to determine the final verdict for each package:

```
1. IF any source flags the package as MALICIOUS
       --> Final Verdict = MALICIOUS

2. ELSE IF any source flags the package as ADVISORY or SUSPICIOUS
       --> Final Verdict = ADVISORY

3. ELSE
       --> Final Verdict = CLEAN
```

> [!IMPORTANT]
> A single `MALICIOUS` flag from any source overrides all other signals. This is a deliberate design choice -- false negatives (missing real malware) are far more dangerous than false positives in a supply chain security context. Suspected false positives are later filtered by the AI intent analysis in [Stage 5](./04-static-analysis-and-ai.md).

---

## Output: Threat Intelligence Report

Each package receives a row in the threat intelligence report:

| Package | Ecosystem | Version | Verdict | Source(s) | Evidence |
|---------|-----------|---------|---------|-----------|----------|
| `evil-requests` | PyPI | 1.0.0 | MALICIOUS | OSV MAL-, Blocklist | MAL-2024-1234, manual report |
| `event-stream` | npm | 3.3.6 | ADVISORY | GHSA | GHSA-xxxx-xxxx-xxxx |
| `requets` | PyPI | 0.1.0 | SUSPICIOUS | Typosquat | Levenshtein=1 to "requests" |
| `flask` | PyPI | 2.3.0 | CLEAN | -- | -- |

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [System Overview](./01-system-overview.md) | High-level pipeline architecture |
| [SBOM & Vulnerability](./02-sbom-and-vulnerability.md) | SBOM parsing and CVE scoring |
| [Static Analysis & AI](./04-static-analysis-and-ai.md) | Code-level verification of flagged packages |
| [Runtime Monitoring](./05-runtime-monitoring.md) | Live container behavioural analysis |
