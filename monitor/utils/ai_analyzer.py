"""
Supply Chain Sentinel -- AI-Powered Code Intelligence Engine (Layer 6)
=======================================================================
Integrates Google Gemini to provide deep semantic analysis of suspicious
source code discovered during static scanning.

Capabilities:
  1. INTENT ANALYSIS     -- Determine what malicious code is trying to do
  2. DE-OBFUSCATION      -- Reverse obfuscated payloads into readable code
  3. FALSE POSITIVE GATE -- Filter benign code misidentified by regex/AST
  4. ZERO-DAY DISCOVERY  -- Find accidental vulnerabilities (SQLi, RCE, etc.)
  5. EXECUTIVE SUMMARY   -- SOC-ready incident report from raw scan data
  6. DEPENDENCY RISK     -- Assess supply chain risk in dependency trees

Architecture:
  This module is invoked AFTER the static scanner and AST engine have
  flagged suspicious files. Only flagged artifacts are sent to the LLM,
  keeping API costs low and latency minimal.

Provider: Google Gemini (google-generativeai SDK)
"""

import json
import logging
import os
import time
from typing import Dict, List, Optional, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markup import escape

from .config import step_header

console = Console()
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

from .config import GEMINI_API_KEYS, SENTINEL_AI_MODEL

_current_key_index = 0
GEMINI_MODEL = SENTINEL_AI_MODEL
AI_MAX_FILE_SIZE = 64 * 1024  # 64 KB max per file sent to LLM
AI_REQUEST_DELAY = 1.0  # seconds between LLM calls (utilizing rotation to handle rate limits)

# ═══════════════════════════════════════════════════════════════
# GEMINI CLIENT INITIALIZATION
# ═══════════════════════════════════════════════════════════════

_gemini_model = None
_ai_available = True

def _init_gemini():
    """Lazy-initialize the Gemini client on first use."""
    global _gemini_model, _ai_available, _current_key_index

    if not _ai_available:
        return False

    if _gemini_model is not None:
        return True

    if not GEMINI_API_KEYS or _current_key_index >= len(GEMINI_API_KEYS):
        logger.warning("No active GEMINI_API_KEYS available. AI analysis disabled.")
        _ai_available = False
        return False

    api_key = GEMINI_API_KEYS[_current_key_index]
    if not api_key:
        logger.warning(f"Gemini API Key at index {_current_key_index} is empty. Trying next key...")
        _current_key_index += 1
        return _init_gemini()

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        _gemini_model = client
        _ai_available = True
        masked_key = api_key[:6] + "..." + api_key[-4:] if len(api_key) > 10 else "..."
        logger.info(f"Gemini AI engine initialized with key index {_current_key_index} ({masked_key}) (model: {GEMINI_MODEL})")
        return True
    except ImportError:
        logger.warning("google-genai not installed. Run: pip install google-genai")
        _ai_available = False
        return False
    except Exception as e:
        logger.warning(f"Failed to initialize Gemini with key index {_current_key_index}: {e}. Trying next key...")
        _current_key_index += 1
        return _init_gemini()


def _call_gemini(prompt: str, max_retries: int = 2) -> str:
    """Send a prompt to Gemini and return the text response."""
    global _current_key_index, _gemini_model, _ai_available
    if not _init_gemini():
        return ""

    for attempt in range(max_retries + 1):
        try:
            response = _gemini_model.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            return response.text.strip()
        except Exception as e:
            err_str = str(e)
            if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str or "quota" in err_str.lower():
                if _current_key_index + 1 < len(GEMINI_API_KEYS):
                    _current_key_index += 1
                    logger.warning(f"[!] Quota exhausted for Gemini API Key index {_current_key_index - 1}. Rotating to next key (index {_current_key_index})...")
                    _gemini_model = None  # Force re-initialization
                    return _call_gemini(prompt, max_retries)
                else:
                    _ai_available = False
                    logger.error("[!] All Gemini API Keys in rotation pool are exhausted. Disabling AI for the remainder of this session.")
                    return ""
                
            if attempt < max_retries:
                wait = 2 ** attempt
                logger.warning(f"Gemini API error (attempt {attempt + 1}): {e}. Retrying in {wait}s...")
                time.sleep(wait)
            else:
                logger.error(f"Gemini API failed after {max_retries + 1} attempts: {e}")
                return ""


def _parse_json_response(raw: str) -> Dict:
    """Extract JSON from an LLM response that may contain markdown fences."""
    text = raw.strip()
    # Strip markdown code fences
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json) and last line (```)
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass
    return {}


# ═══════════════════════════════════════════════════════════════
# CAPABILITY 1: INTENT ANALYSIS
# ═══════════════════════════════════════════════════════════════

_INTENT_SYSTEM_PROMPT = """You are SENTINEL-AI, a senior cybersecurity reverse engineer specializing in supply chain malware analysis. You analyze source code extracted from software packages to determine if it contains malicious intent.

RULES:
- Be precise and technical. Cite specific line numbers and function names.
- Distinguish between genuinely malicious code and legitimate utility code that happens to use sensitive APIs.
- Focus on BEHAVIORAL INTENT, not just API usage. eval() in a template engine is benign; eval() decoding a Base64 payload from a remote server is malicious.
- Output ONLY valid JSON. No markdown, no commentary outside the JSON.

OUTPUT FORMAT (strict JSON):
{
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "BENIGN",
  "confidence": <float 0.0-1.0>,
  "intent_summary": "<1-2 sentence description of what the code does>",
  "attack_vector": "<category: data_exfiltration | credential_theft | cryptomining | backdoor | ransomware | sabotage | reconnaissance | none>",
  "evidence": ["<specific code evidence 1>", "<specific code evidence 2>"]
}"""


def analyze_intent(filepath: str, code: str) -> Dict:
    """
    Analyze a source file for malicious intent using the LLM.

    Args:
        filepath: Relative path to the file (for context).
        code: The source code content.

    Returns:
        Dict with verdict, confidence, intent_summary, attack_vector, evidence.
    """
    if not _init_gemini():
        return {}

    # Truncate very large files to stay within token limits
    truncated = code[:AI_MAX_FILE_SIZE]
    if len(code) > AI_MAX_FILE_SIZE:
        truncated += "\n\n// ... [TRUNCATED - file exceeds 64KB] ..."

    prompt = f"""{_INTENT_SYSTEM_PROMPT}

FILE: {filepath}
SOURCE CODE:
```
{truncated}
```

Analyze this code and return the JSON verdict."""

    raw = _call_gemini(prompt)
    result = _parse_json_response(raw)
    if result:
        result["file"] = filepath
    time.sleep(AI_REQUEST_DELAY)
    return result


# ═══════════════════════════════════════════════════════════════
# CAPABILITY 2: AUTOMATED DE-OBFUSCATION
# ═══════════════════════════════════════════════════════════════

_DEOBFUSCATION_PROMPT = """You are SENTINEL-AI, a malware reverse engineer. You specialize in de-obfuscating supply chain malware.

Given the following obfuscated code snippet, reverse-engineer it into clean, readable, equivalent code. Explain each obfuscation layer you peeled back.

RULES:
- Decode all Base64 strings inline and show the decoded value.
- Expand all hex escape sequences into readable strings.
- Resolve all String.fromCharCode() / chr() sequences into readable strings.
- Unwrap nested eval() / Function() / exec() calls to show the final payload.
- Output ONLY valid JSON. No markdown outside JSON.

OUTPUT FORMAT (strict JSON):
{
  "original_technique": "<obfuscation method used: base64 | hex_escape | char_code | eval_chain | string_concat | mixed>",
  "deobfuscated_code": "<the clean readable equivalent code>",
  "hidden_payload": "<what the code actually does when executed>",
  "iocs_extracted": ["<any URLs, IPs, domains, or file paths found after deobfuscation>"]
}"""


def deobfuscate_code(filepath: str, code: str) -> Dict:
    """
    Attempt to de-obfuscate suspicious code using the LLM.

    Args:
        filepath: Relative path to the file.
        code: The obfuscated source code.

    Returns:
        Dict with deobfuscation results.
    """
    if not _init_gemini():
        return {}

    truncated = code[:AI_MAX_FILE_SIZE]

    prompt = f"""{_DEOBFUSCATION_PROMPT}

FILE: {filepath}
OBFUSCATED CODE:
```
{truncated}
```

De-obfuscate this code and return the JSON result."""

    raw = _call_gemini(prompt)
    result = _parse_json_response(raw)
    if result:
        result["file"] = filepath
    time.sleep(AI_REQUEST_DELAY)
    return result


# ═══════════════════════════════════════════════════════════════
# CAPABILITY 3: FALSE POSITIVE FILTERING
# ═══════════════════════════════════════════════════════════════

_FALSE_POSITIVE_PROMPT = """You are SENTINEL-AI, a senior security analyst performing triage on static analysis alerts. Your job is to determine if an alert is a TRUE POSITIVE (genuinely suspicious) or a FALSE POSITIVE (benign code that triggered a pattern-based rule).

You will receive:
1. The alert type (e.g., "eval() call detected", "Base64 string found")
2. The source code context around the alert
3. The file path

RULES:
- Consider the CONTEXT. An eval() inside a template engine or test harness is usually benign.
- Base64 strings in documentation, comments, or test fixtures are usually benign.
- Network calls in a legitimate HTTP client library are benign.
- ONLY mark as false_positive if you are confident the code is NOT malicious.
- Output ONLY valid JSON.

OUTPUT FORMAT (strict JSON):
{
  "is_false_positive": <boolean>,
  "confidence": <float 0.0-1.0>,
  "reason": "<1 sentence explaining why this is or is not a false positive>"
}"""


def check_false_positive(filepath: str, code_context: str, alert_type: str) -> Dict:
    """
    Ask the LLM whether a specific static analysis alert is a false positive.

    Args:
        filepath: Relative path to the file.
        code_context: The code surrounding the alert (typically 20-30 lines).
        alert_type: Description of what triggered the alert.

    Returns:
        Dict with is_false_positive, confidence, reason.
    """
    if not _init_gemini():
        return {}

    prompt = f"""{_FALSE_POSITIVE_PROMPT}

ALERT TYPE: {alert_type}
FILE: {filepath}
CODE CONTEXT:
```
{code_context}
```

Is this a false positive? Return the JSON verdict."""

    raw = _call_gemini(prompt)
    result = _parse_json_response(raw)
    time.sleep(AI_REQUEST_DELAY)
    return result


# ═══════════════════════════════════════════════════════════════
# CAPABILITY 4: ZERO-DAY VULNERABILITY DISCOVERY
# ═══════════════════════════════════════════════════════════════

_ZERODAY_PROMPT = """You are SENTINEL-AI, a vulnerability researcher. You analyze source code from third-party packages to find accidental security vulnerabilities that have NOT been assigned a CVE yet (zero-day vulnerabilities).

Focus on these vulnerability classes:
- SQL Injection (unsanitized user input in queries)
- Command Injection (user input passed to os.system, exec, child_process)
- Path Traversal (user input in file paths without sanitization)
- Insecure Deserialization (pickle.loads, yaml.load without SafeLoader, eval of user data)
- ReDoS (Regular Expression Denial of Service -- catastrophic backtracking patterns)
- Prototype Pollution (JavaScript __proto__ / constructor.prototype manipulation)
- Server-Side Request Forgery (SSRF -- user-controlled URLs in server-side requests)
- Hardcoded Credentials (API keys, passwords, tokens embedded in source)

RULES:
- ONLY report genuine vulnerabilities, not theoretical risks.
- Each finding must reference specific code (line numbers, function names).
- Output ONLY valid JSON.

OUTPUT FORMAT (strict JSON):
{
  "vulnerabilities_found": <integer>,
  "findings": [
    {
      "type": "<vulnerability class>",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "location": "<function or line reference>",
      "description": "<what the vulnerability is>",
      "exploitability": "<how an attacker could exploit this>"
    }
  ]
}"""


def discover_zero_days(filepath: str, code: str) -> Dict:
    """
    Analyze source code for undisclosed vulnerabilities.

    Args:
        filepath: Relative path to the file.
        code: The source code to audit.

    Returns:
        Dict with vulnerabilities_found count and findings list.
    """
    if not _init_gemini():
        return {}

    truncated = code[:AI_MAX_FILE_SIZE]

    prompt = f"""{_ZERODAY_PROMPT}

FILE: {filepath}
SOURCE CODE:
```
{truncated}
```

Audit this code for zero-day vulnerabilities and return the JSON result."""

    raw = _call_gemini(prompt)
    result = _parse_json_response(raw)
    if result:
        result["file"] = filepath
    time.sleep(AI_REQUEST_DELAY)
    return result


# ═══════════════════════════════════════════════════════════════
# CAPABILITY 5: EXECUTIVE SUMMARY (SOC ANALYST)
# ═══════════════════════════════════════════════════════════════

_EXECUTIVE_PROMPT = """You are SENTINEL-AI, acting as a Level 3 SOC (Security Operations Center) Analyst. You are writing an executive incident summary for a security team.

You will receive raw scan data from a supply chain security tool. Your job is to synthesize ALL findings into a concise, actionable incident report.

RULES:
- Write for a CISO or security lead who needs to make a fast decision.
- Lead with the verdict and recommended action.
- Cite specific package names, CVE IDs, and IOCs.
- Use professional incident response language.
- Output ONLY valid JSON.

OUTPUT FORMAT (strict JSON):
{
  "overall_risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN",
  "verdict": "<1 sentence overall verdict>",
  "recommended_action": "QUARANTINE" | "INVESTIGATE" | "MONITOR" | "APPROVE",
  "executive_summary": "<2-4 sentence summary for leadership>",
  "key_findings": ["<finding 1>", "<finding 2>", "<finding 3>"],
  "affected_packages": ["<package1>", "<package2>"],
  "ioc_highlights": ["<critical IOC 1>", "<critical IOC 2>"]
}"""


def generate_executive_summary(scan_data: Dict) -> Dict:
    """
    Generate an executive-level SOC summary from raw scan results.

    Args:
        scan_data: Dict containing all scan outputs (vulns, IOCs, AST findings, etc.)

    Returns:
        Dict with overall_risk_level, verdict, executive_summary, etc.
    """
    if not _init_gemini():
        return {}

    # Serialize scan data to a compact JSON representation
    compact = json.dumps(scan_data, indent=None, default=str)
    # Truncate if too large for context window
    if len(compact) > 100_000:
        compact = compact[:100_000] + "\n... [TRUNCATED]"

    prompt = f"""{_EXECUTIVE_PROMPT}

RAW SCAN DATA:
```json
{compact}
```

Synthesize this data into an executive incident summary. Return the JSON result."""

    raw = _call_gemini(prompt)
    result = _parse_json_response(raw)
    time.sleep(AI_REQUEST_DELAY)
    return result


# ═══════════════════════════════════════════════════════════════
# CAPABILITY 6: DEPENDENCY RISK ANALYSIS
# ═══════════════════════════════════════════════════════════════

_DEPENDENCY_RISK_PROMPT = """You are SENTINEL-AI, a supply chain security analyst. You assess the risk of a project's dependency tree based on package metadata.

You will receive a list of dependencies with their names, versions, and ecosystems. Analyze for:
1. Known historically compromised packages (e.g., event-stream, ua-parser-js, colors)
2. Packages with suspicious naming (typosquatting of popular packages)
3. Unusual version patterns (pre-release versions, yanked ranges)
4. Packages with very few downloads or unknown maintainers (if inferable from name)
5. Excessive transitive dependency depth creating attack surface

RULES:
- Be factual. Only flag real risks based on known incidents or clear naming anomalies.
- Do NOT flag well-known popular packages as risky.
- Output ONLY valid JSON.

OUTPUT FORMAT (strict JSON):
{
  "overall_supply_chain_risk": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "risk_summary": "<1-2 sentence summary of the dependency tree risk>",
  "flagged_packages": [
    {
      "name": "<package name>",
      "risk": "<what the risk is>",
      "recommendation": "<what to do about it>"
    }
  ],
  "total_dependencies": <integer>,
  "high_risk_count": <integer>
}"""


def analyze_dependency_risk(packages: List[Dict]) -> Dict:
    """
    Analyze the full dependency tree for supply chain risks.

    Args:
        packages: List of package dicts with name, version, ecosystem.

    Returns:
        Dict with supply chain risk assessment.
    """
    if not _init_gemini():
        return {}

    # Build compact package list
    pkg_list = [
        {"name": p.get("name"), "version": p.get("version"), "ecosystem": p.get("ecosystem", "unknown")}
        for p in packages
    ]
    compact = json.dumps(pkg_list, indent=None)
    if len(compact) > 80_000:
        compact = compact[:80_000] + "\n... [TRUNCATED]"

    prompt = f"""{_DEPENDENCY_RISK_PROMPT}

DEPENDENCY LIST:
```json
{compact}
```

Analyze this dependency tree for supply chain risks. Return the JSON result."""

    raw = _call_gemini(prompt)
    result = _parse_json_response(raw)
    time.sleep(AI_REQUEST_DELAY)
    return result


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR: FULL AI PIPELINE FOR A PACKAGE
# ═══════════════════════════════════════════════════════════════

def analyze_package_ai(
    package_name: str,
    package_path: str,
    ast_findings: List[Dict],
    scan_results: Dict,
) -> Dict:
    """
    Run the full AI analysis pipeline on a single package.

    This is the main entry point called by static_analysis.py.
    It runs intent analysis, de-obfuscation, false positive filtering,
    and zero-day discovery on files that were flagged by the AST engine.

    Args:
        package_name: Name of the package.
        package_path: Path to the package directory.
        ast_findings: List of AST finding dicts from ast_scanner.py.
        scan_results: Full scan results dict from static_analysis.py.

    Returns:
        Dict with all AI analysis results consolidated.
    """
    if not _init_gemini():
        return {"ai_available": False}

    ai_results = {
        "ai_available": True,
        "intent_analyses": [],
        "deobfuscations": [],
        "false_positives": [],
        "zero_day_findings": [],
    }

    # Collect unique files that were flagged
    flagged_files = set()
    for finding in ast_findings:
        if isinstance(finding, dict) and finding.get("file"):
            flagged_files.add(finding["file"])

    # Also check files with base64 or hex obfuscation
    for b64 in scan_results.get("base64_strings", []):
        if b64.get("file"):
            flagged_files.add(b64["file"])
    for hx in scan_results.get("hex_strings", []):
        if hx.get("file"):
            flagged_files.add(hx["file"])

    # Cap at 5 files to control API costs
    flagged_list = list(flagged_files)[:5]

    for rel_path in flagged_list:
        # Resolve the full file path
        full_path = os.path.join(package_path, rel_path)
        if not os.path.isfile(full_path):
            # Try without package_path prefix (rel_path might already be absolute-ish)
            if os.path.isfile(rel_path):
                full_path = rel_path
            else:
                continue

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
        except Exception:
            continue

        if not code.strip():
            continue

        # 1. Intent Analysis
        intent = analyze_intent(rel_path, code)
        if intent:
            ai_results["intent_analyses"].append(intent)

        # 2. De-obfuscation (only if obfuscation indicators exist)
        has_obfuscation = any(
            b64.get("file") == rel_path for b64 in scan_results.get("base64_strings", [])
        ) or any(
            hx.get("file") == rel_path for hx in scan_results.get("hex_strings", [])
        )
        if has_obfuscation:
            deobf = deobfuscate_code(rel_path, code)
            if deobf:
                ai_results["deobfuscations"].append(deobf)

        # 3. False Positive Check (on each AST finding for this file)
        for finding in ast_findings:
            if isinstance(finding, dict) and finding.get("file") == rel_path:
                alert_type = finding.get("type", "unknown")
                desc = finding.get("description", "")
                # Get ~30 lines around the finding
                line_num = finding.get("line", 1)
                lines = code.split("\n")
                start = max(0, line_num - 15)
                end = min(len(lines), line_num + 15)
                context = "\n".join(lines[start:end])

                fp_check = check_false_positive(rel_path, context, f"{alert_type}: {desc}")
                if fp_check:
                    fp_check["original_alert"] = f"{alert_type}: {desc}"
                    fp_check["file"] = rel_path
                    ai_results["false_positives"].append(fp_check)

        # 4. Zero-Day Discovery
        zeroday = discover_zero_days(rel_path, code)
        if zeroday and zeroday.get("vulnerabilities_found", 0) > 0:
            ai_results["zero_day_findings"].append(zeroday)

    return ai_results


# ═══════════════════════════════════════════════════════════════
# DISPLAY: RICH TERMINAL OUTPUT
# ═══════════════════════════════════════════════════════════════

def display_ai_results(package_name: str, ai_results: Dict) -> None:
    """
    Display AI analysis results in a professional Rich terminal layout.

    Args:
        package_name: Name of the package analyzed.
        ai_results: Dict returned by analyze_package_ai().
    """
    if not ai_results or not ai_results.get("ai_available"):
        return

    has_content = (
        ai_results.get("intent_analyses")
        or ai_results.get("deobfuscations")
        or ai_results.get("zero_day_findings")
    )
    if not has_content:
        return

    # ── Intent Analysis Table ──
    intents = ai_results.get("intent_analyses", [])
    if intents:
        intent_table = Table(
            show_header=True,
            header_style="bold white on dark_magenta",
            border_style="magenta",
            padding=(0, 1),
            show_lines=True,
            expand=False,
        )
        intent_table.add_column("File", style="cyan", min_width=20)
        intent_table.add_column("Verdict", justify="center", min_width=12)
        intent_table.add_column("Confidence", justify="center", width=12)
        intent_table.add_column("Attack Vector", style="yellow", min_width=18)
        intent_table.add_column("Intent Summary", style="white", min_width=40)

        for intent in intents:
            verdict = intent.get("verdict", "UNKNOWN")
            if verdict == "MALICIOUS":
                verdict_display = "[bold white on red] MALICIOUS [/]"
            elif verdict == "SUSPICIOUS":
                verdict_display = "[bold black on yellow] SUSPICIOUS [/]"
            else:
                verdict_display = "[bold white on green] BENIGN [/]"

            confidence = intent.get("confidence", 0)
            conf_display = f"{confidence:.0%}"

            intent_table.add_row(
                escape(str(intent.get("file", "?"))),
                verdict_display,
                conf_display,
                escape(str(intent.get("attack_vector", "none"))),
                escape(str(intent.get("intent_summary", "N/A"))),
            )

        console.print(Panel(
            intent_table,
            title=f"[bold magenta][AI] Intent Analysis for '{package_name}'[/]",
            border_style="magenta",
            padding=(1, 2),
        ))

    # ── De-obfuscation Results ──
    deobfs = ai_results.get("deobfuscations", [])
    if deobfs:
        for deobf in deobfs:
            deobf_table = Table(
                show_header=False,
                border_style="red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            deobf_table.add_column("Field", style="bold yellow", width=22)
            deobf_table.add_column("Value", style="white", min_width=60)

            deobf_table.add_row("File", escape(str(deobf.get("file", "?"))))
            deobf_table.add_row("Technique", escape(str(deobf.get("original_technique", "unknown"))))
            deobf_table.add_row("Hidden Payload", escape(str(deobf.get("hidden_payload", "N/A"))))
            deobf_table.add_row("Deobfuscated Code", escape(str(deobf.get("deobfuscated_code", "N/A"))[:200]))

            iocs = deobf.get("iocs_extracted", [])
            if iocs:
                deobf_table.add_row("Extracted IOCs", escape(", ".join(str(i) for i in iocs)))

            console.print(Panel(
                deobf_table,
                title=f"[bold red][AI] De-Obfuscation Result[/]",
                border_style="red",
                padding=(1, 2),
            ))

    # ── False Positive Filter ──
    fps = ai_results.get("false_positives", [])
    confirmed_fps = [fp for fp in fps if fp.get("is_false_positive")]
    if confirmed_fps:
        fp_table = Table(
            show_header=True,
            header_style="bold white on dark_green",
            border_style="green",
            padding=(0, 1),
            show_lines=True,
            expand=False,
        )
        fp_table.add_column("File", style="cyan", min_width=20)
        fp_table.add_column("Original Alert", style="yellow", min_width=30)
        fp_table.add_column("AI Verdict", justify="center", min_width=15)
        fp_table.add_column("Reason", style="white", min_width=30)

        for fp in confirmed_fps:
            fp_table.add_row(
                escape(str(fp.get("file", "?"))),
                escape(str(fp.get("original_alert", "?"))),
                "[bold green]FALSE POSITIVE[/]",
                escape(str(fp.get("reason", "N/A"))),
            )

        console.print(Panel(
            fp_table,
            title=f"[bold green][AI] False Positive Filter for '{package_name}'[/]",
            border_style="green",
            padding=(1, 2),
        ))

    # ── Zero-Day Discovery ──
    zerodays = ai_results.get("zero_day_findings", [])
    if zerodays:
        for zd in zerodays:
            findings = zd.get("findings", [])
            if not findings:
                continue

            zd_table = Table(
                show_header=True,
                header_style="bold white on red",
                border_style="bright_red",
                padding=(0, 1),
                show_lines=True,
                expand=False,
            )
            zd_table.add_column("Type", style="bold red", min_width=20)
            zd_table.add_column("Severity", justify="center", min_width=10)
            zd_table.add_column("Location", style="cyan", min_width=20)
            zd_table.add_column("Description", style="white", min_width=35)
            zd_table.add_column("Exploitability", style="yellow", min_width=25)

            for finding in findings:
                severity = finding.get("severity", "UNKNOWN")
                if severity == "CRITICAL":
                    sev_display = "[bold white on red] CRITICAL [/]"
                elif severity == "HIGH":
                    sev_display = "[bold red] HIGH [/]"
                elif severity == "MEDIUM":
                    sev_display = "[bold yellow] MEDIUM [/]"
                else:
                    sev_display = "[bold blue] LOW [/]"

                zd_table.add_row(
                    escape(str(finding.get("type", "?"))),
                    sev_display,
                    escape(str(finding.get("location", "?"))),
                    escape(str(finding.get("description", "N/A"))),
                    escape(str(finding.get("exploitability", "N/A"))),
                )

            console.print(Panel(
                zd_table,
                title=f"[bold bright_red][AI] Zero-Day Vulnerability Discovery in '{zd.get('file', package_name)}'[/]",
                border_style="bright_red",
                padding=(1, 2),
            ))


def display_executive_summary(summary: Dict) -> None:
    """
    Display the AI-generated executive summary in a prominent Rich panel.

    Args:
        summary: Dict returned by generate_executive_summary().
    """
    if not summary:
        return

    risk = summary.get("overall_risk_level", "UNKNOWN")
    risk_colors = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold blue",
        "CLEAN": "bold green",
    }
    risk_style = risk_colors.get(risk, "bold white")

    verdict = summary.get("verdict", "No verdict available.")
    action = summary.get("recommended_action", "INVESTIGATE")
    exec_summary = summary.get("executive_summary", "")
    findings = summary.get("key_findings", [])
    affected = summary.get("affected_packages", [])
    iocs = summary.get("ioc_highlights", [])

    action_colors = {
        "QUARANTINE": "bold white on red",
        "INVESTIGATE": "bold yellow",
        "MONITOR": "bold blue",
        "APPROVE": "bold green",
    }
    action_style = action_colors.get(action, "bold white")

    # Build the summary content
    content_lines = []
    content_lines.append(f"  [{risk_style}]RISK LEVEL: {risk}[/]")
    content_lines.append(f"  [{action_style}]RECOMMENDED ACTION: {action}[/]")
    content_lines.append("")
    content_lines.append(f"  [bold white]VERDICT:[/] {escape(verdict)}")
    content_lines.append("")

    if exec_summary:
        content_lines.append(f"  [bold white]EXECUTIVE SUMMARY:[/]")
        content_lines.append(f"  {escape(exec_summary)}")
        content_lines.append("")

    if findings:
        content_lines.append(f"  [bold white]KEY FINDINGS:[/]")
        for i, f in enumerate(findings[:5], 1):
            content_lines.append(f"    {i}. {escape(str(f))}")
        content_lines.append("")

    if affected:
        content_lines.append(f"  [bold white]AFFECTED PACKAGES:[/] {', '.join(escape(str(a)) for a in affected)}")

    if iocs:
        content_lines.append(f"  [bold white]IOC HIGHLIGHTS:[/]")
        for ioc in iocs[:5]:
            content_lines.append(f"    [red]>>[/] {escape(str(ioc))}")

    console.print(Panel(
        "\n".join(content_lines),
        title="[bold bright_cyan]<<<  SENTINEL AI -- EXECUTIVE INCIDENT SUMMARY  >>>[/]",
        border_style="bright_cyan",
        padding=(1, 2),
    ))


def display_dependency_risk(risk_data: Dict) -> None:
    """
    Display the AI-generated dependency risk analysis.

    Args:
        risk_data: Dict returned by analyze_dependency_risk().
    """
    if not risk_data:
        return

    risk = risk_data.get("overall_supply_chain_risk", "UNKNOWN")
    risk_colors = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }
    risk_style = risk_colors.get(risk, "bold white")

    flagged = risk_data.get("flagged_packages", [])
    total = risk_data.get("total_dependencies", 0)
    high_risk = risk_data.get("high_risk_count", 0)
    summary = risk_data.get("risk_summary", "")

    if not flagged and risk in ("LOW",):
        console.print(f"  [bold green][AI] Dependency Risk: LOW -- {escape(summary)}[/]")
        return

    content_lines = []
    content_lines.append(f"  [{risk_style}]SUPPLY CHAIN RISK: {risk}[/]")
    content_lines.append(f"  [dim]Total Dependencies: {total} | High Risk: {high_risk}[/]")
    content_lines.append(f"  {escape(summary)}")

    if flagged:
        content_lines.append("")
        dep_table = Table(
            show_header=True,
            header_style="bold white on dark_red",
            border_style="red",
            padding=(0, 1),
            show_lines=True,
            expand=False,
        )
        dep_table.add_column("Package", style="bold yellow", min_width=20)
        dep_table.add_column("Risk", style="red", min_width=35)
        dep_table.add_column("Recommendation", style="cyan", min_width=25)

        for pkg in flagged:
            dep_table.add_row(
                escape(str(pkg.get("name", "?"))),
                escape(str(pkg.get("risk", "?"))),
                escape(str(pkg.get("recommendation", "?"))),
            )

        console.print(Panel(
            dep_table,
            title="[bold red][AI] Dependency Risk Analysis[/]",
            border_style="red",
            padding=(1, 2),
        ))
    else:
        console.print(Panel(
            "\n".join(content_lines),
            title="[bold yellow][AI] Dependency Risk Analysis[/]",
            border_style="yellow",
            padding=(1, 2),
        ))
