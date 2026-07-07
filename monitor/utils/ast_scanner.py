"""
ast_scanner.py -- Multi-language AST security scanner using Tree-sitter.

Detects suspicious code patterns in Python, JavaScript, Go, and Ruby source
files by parsing them into concrete syntax trees via Tree-sitter and walking
the resulting nodes.

Output format (unchanged from prior version):
  Each finding is a dict with keys: type, file, line, description
"""

import json
import logging
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tree-sitter initialisation
# ---------------------------------------------------------------------------
# Each language grammar is loaded independently so a missing grammar only
# disables scanning for that one language.

try:
    from tree_sitter import Language, Parser
    TREESITTER_AVAILABLE = True
except ImportError:
    TREESITTER_AVAILABLE = False
    logger.warning("tree-sitter not found. AST scanning will be disabled.")

# -- Python ----------------------------------------------------------------
try:
    import tree_sitter_python as _tspython
    PY_LANGUAGE = Language(_tspython.language())
except Exception:
    PY_LANGUAGE = None
    if TREESITTER_AVAILABLE:
        logger.warning("tree-sitter-python grammar not found. Python AST scanning disabled.")

# -- JavaScript ------------------------------------------------------------
try:
    import tree_sitter_javascript as _tsjavascript
    JS_LANGUAGE = Language(_tsjavascript.language())
except Exception:
    JS_LANGUAGE = None
    if TREESITTER_AVAILABLE:
        logger.warning("tree-sitter-javascript grammar not found. JS AST scanning disabled.")

# -- Go --------------------------------------------------------------------
try:
    import tree_sitter_go as _tsgo
    GO_LANGUAGE = Language(_tsgo.language())
except Exception:
    GO_LANGUAGE = None
    if TREESITTER_AVAILABLE:
        logger.warning("tree-sitter-go grammar not found. Go AST scanning disabled.")

# -- Ruby ------------------------------------------------------------------
try:
    import tree_sitter_ruby as _tsruby
    RB_LANGUAGE = Language(_tsruby.language())
except Exception:
    RB_LANGUAGE = None
    if TREESITTER_AVAILABLE:
        logger.warning("tree-sitter-ruby grammar not found. Ruby AST scanning disabled.")

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

SENSITIVE_FILES = [
    '/etc/passwd', '/etc/shadow', '.ssh/id_rsa', '.ssh/id_dsa',
    '.git/config', '/etc/hosts', 'system32/drivers/etc/hosts', 'id_rsa'
]

SENSITIVE_ENV_KEYS = [
    'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN',
    'NPM_TOKEN', 'DB_PASSWORD', 'DATABASE_URL', 'SECRET_KEY', 'JWT_SECRET'
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse(language, content):
    """Parse *content* (str) with the given Tree-sitter Language.

    Returns the root node of the tree, or None on failure.
    """
    if not TREESITTER_AVAILABLE or language is None:
        return None
    try:
        parser = Parser(language)
        tree = parser.parse(content.encode("utf-8"))
        return tree.root_node
    except Exception as exc:
        logger.debug("Tree-sitter parse error: %s", exc)
        return None


def _walk(node):
    """Depth-first generator over every node in a Tree-sitter tree."""
    yield node
    for child in node.children:
        yield from _walk(child)


def _node_text(node):
    """Return the source text of *node* as a Python str."""
    if node is None:
        return ""
    return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text)


def _line(node):
    """1-indexed line number of *node*."""
    return node.start_point[0] + 1


def _matches_sensitive_key(value):
    """Return True if *value* matches any SENSITIVE_ENV_KEYS entry."""
    upper = value.upper()
    return any(sek in upper for sek in SENSITIVE_ENV_KEYS)


def _matches_sensitive_file(value):
    """Return True if *value* matches any SENSITIVE_FILES entry."""
    lower = value.lower()
    return any(sf in lower for sf in SENSITIVE_FILES)


def _strip_quotes(text):
    """Strip surrounding single/double/backtick quotes from a string literal."""
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"', '`'):
        return text[1:-1]
    return text

# ---------------------------------------------------------------------------
# Python analyser
# ---------------------------------------------------------------------------

def analyze_python_ast(filepath, content):
    """Detect suspicious patterns in Python source via Tree-sitter."""
    findings = []
    root = _parse(PY_LANGUAGE, content)

    if root is None:
        if PY_LANGUAGE is None:
            findings.append({
                "type": "AST Scanning Disabled",
                "file": filepath,
                "line": 0,
                "description": "tree-sitter-python grammar not installed. Python AST scanning skipped."
            })
        return findings

    for node in _walk(root):
        # --- call expressions ------------------------------------------------
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node is None:
                continue
            args_node = node.child_by_field_name("arguments")

            # Direct calls: eval(), exec(), __import__()
            if func_node.type == "identifier":
                name = _node_text(func_node)
                if name in ("eval", "exec"):
                    findings.append({
                        "type": "Dynamic Execution",
                        "file": filepath,
                        "line": _line(node),
                        "description": f"Use of `{name}()` detected. This could execute arbitrary malicious code."
                    })
                elif name == "__import__":
                    findings.append({
                        "type": "Suspicious Import",
                        "file": filepath,
                        "line": _line(node),
                        "description": "Dynamic `__import__()` call detected."
                    })

                # open() with sensitive files
                if name == "open" and args_node is not None:
                    first_arg = _first_string_arg(args_node)
                    if first_arg is not None and _matches_sensitive_file(first_arg):
                        findings.append({
                            "type": "Sensitive File Access",
                            "file": filepath,
                            "line": _line(node),
                            "description": f"Attempt to open sensitive file: `{first_arg}`"
                        })

            # Attribute calls: os.system(), subprocess.run(), bytes.fromhex(), os.getenv()
            if func_node.type == "attribute":
                obj_node = func_node.child_by_field_name("object")
                attr_node = func_node.child_by_field_name("attribute")
                if obj_node is None or attr_node is None:
                    continue
                base = _node_text(obj_node)
                attr = _node_text(attr_node)

                if base == "bytes" and attr == "fromhex":
                    findings.append({
                        "type": "Obfuscation",
                        "file": filepath,
                        "line": _line(node),
                        "description": "Use of `bytes.fromhex()` detected, often used to hide payloads."
                    })

                if base == "os" and attr in ("system", "popen"):
                    findings.append({
                        "type": "System Command Execution",
                        "file": filepath,
                        "line": _line(node),
                        "description": f"Use of `os.{attr}()` detected."
                    })

                if base == "subprocess" and attr in ("Popen", "run", "call", "check_call", "check_output"):
                    findings.append({
                        "type": "System Command Execution",
                        "file": filepath,
                        "line": _line(node),
                        "description": f"Use of `subprocess.{attr}()` detected."
                    })

                if base == "os" and attr == "getenv" and args_node is not None:
                    first_arg = _first_string_arg(args_node)
                    if first_arg is not None and _matches_sensitive_key(first_arg):
                        findings.append({
                            "type": "Credential Theft",
                            "file": filepath,
                            "line": _line(node),
                            "description": f"Access to sensitive environment variable: `{first_arg}`"
                        })

        # --- subscript: os.environ['KEY'] ------------------------------------
        if node.type == "subscript":
            value_node = node.child_by_field_name("value")
            subscript_node = node.child_by_field_name("subscript")

            if value_node is not None and value_node.type == "attribute":
                obj = value_node.child_by_field_name("object")
                attr = value_node.child_by_field_name("attribute")
                if (obj is not None and attr is not None
                        and _node_text(obj) == "os" and _node_text(attr) == "environ"):
                    if subscript_node is not None and subscript_node.type == "string":
                        key = _strip_quotes(_node_text(subscript_node))
                        if _matches_sensitive_key(key):
                            findings.append({
                                "type": "Credential Theft",
                                "file": filepath,
                                "line": _line(node),
                                "description": f"Access to sensitive environment variable: `{key}`"
                            })

        # --- attribute access: ShellExecuteW / ShellExecuteA -----------------
        if node.type == "attribute":
            attr_node = node.child_by_field_name("attribute")
            if attr_node is not None:
                attr_name = _node_text(attr_node)
                if attr_name in ("ShellExecuteW", "ShellExecuteA"):
                    findings.append({
                        "type": "Windows API Execution",
                        "file": filepath,
                        "line": _line(node),
                        "description": f"Use of `{attr_name}` Windows API detected, often used by malware droppers."
                    })

    return findings


def _first_string_arg(args_node):
    """Return the text of the first string-literal argument inside an argument_list node, or None."""
    for child in args_node.children:
        if child.type == "string":
            return _strip_quotes(_node_text(child))
    return None

# ---------------------------------------------------------------------------
# JavaScript analyser
# ---------------------------------------------------------------------------

def analyze_javascript_ast(filepath, content):
    """Detect suspicious patterns in JavaScript source via Tree-sitter."""
    findings = []
    root = _parse(JS_LANGUAGE, content)

    if root is None:
        if JS_LANGUAGE is None:
            findings.append({
                "type": "AST Scanning Disabled",
                "file": filepath,
                "line": 0,
                "description": "tree-sitter-javascript grammar not installed. JS AST scanning skipped."
            })
        return findings

    for node in _walk(root):
        # --- call_expression -------------------------------------------------
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node is None:
                continue

            # Direct calls: eval(), atob()
            if func_node.type == "identifier":
                name = _node_text(func_node)
                if name == "eval":
                    findings.append({
                        "type": "Dynamic Execution",
                        "file": filepath,
                        "line": _line(node),
                        "description": "Use of `eval()` detected. This could execute arbitrary malicious code."
                    })
                elif name == "atob":
                    findings.append({
                        "type": "Obfuscation",
                        "file": filepath,
                        "line": _line(node),
                        "description": "Use of `atob()` (base64 decoding) detected. Often used to decode malicious payloads."
                    })

            # Member calls: String.fromCharCode(), fs.readFile(), etc.
            if func_node.type == "member_expression":
                obj_node = func_node.child_by_field_name("object")
                prop_node = func_node.child_by_field_name("property")
                if obj_node is None or prop_node is None:
                    continue
                obj_name = _node_text(obj_node)
                prop_name = _node_text(prop_node)

                if obj_name == "String" and prop_name == "fromCharCode":
                    findings.append({
                        "type": "Obfuscation",
                        "file": filepath,
                        "line": _line(node),
                        "description": "Use of `String.fromCharCode()` detected. Often used to hide malicious payloads."
                    })

                if prop_name in ("readFile", "readFileSync", "createReadStream"):
                    if args_node is not None:
                        first_arg = _first_js_string_arg(args_node)
                        if first_arg is not None and _matches_sensitive_file(first_arg):
                            findings.append({
                                "type": "Sensitive File Access",
                                "file": filepath,
                                "line": _line(node),
                                "description": f"Attempt to read sensitive file: `{first_arg}`"
                            })

                # child_process usage (exec, execSync, spawn, etc.)
                if obj_name == "child_process" and prop_name in ("exec", "execSync", "spawn", "spawnSync", "fork"):
                    findings.append({
                        "type": "System Command Execution",
                        "file": filepath,
                        "line": _line(node),
                        "description": f"Use of `child_process.{prop_name}()` detected."
                    })

        # --- new_expression: new Function() ----------------------------------
        if node.type == "new_expression":
            constructor = node.child_by_field_name("constructor")
            if constructor is not None and _node_text(constructor) == "Function":
                findings.append({
                    "type": "Dynamic Execution",
                    "file": filepath,
                    "line": _line(node),
                    "description": "Use of `new Function()` detected. Equivalent to eval()."
                })

        # --- member_expression: process.env.KEY ------------------------------
        if node.type == "member_expression":
            obj_node = node.child_by_field_name("object")
            prop_node = node.child_by_field_name("property")
            if (obj_node is not None and obj_node.type == "member_expression"
                    and prop_node is not None):
                inner_obj = obj_node.child_by_field_name("object")
                inner_prop = obj_node.child_by_field_name("property")
                if (inner_obj is not None and inner_prop is not None
                        and _node_text(inner_obj) == "process"
                        and _node_text(inner_prop) == "env"):
                    key = _node_text(prop_node)
                    if _matches_sensitive_key(key):
                        findings.append({
                            "type": "Credential Theft",
                            "file": filepath,
                            "line": _line(node),
                            "description": f"Access to sensitive environment variable: `{key}`"
                        })

        # --- array: hex obfuscation ------------------------------------------
        if node.type == "array":
            for child in node.children:
                if child.type == "string":
                    raw = _node_text(child)
                    if "\\x" in raw:
                        findings.append({
                            "type": "Obfuscation",
                            "file": filepath,
                            "line": _line(node),
                            "description": "Array containing hex-encoded strings (e.g. '\\x...'). Common obfuscation technique."
                        })
                        break

    return findings


def _first_js_string_arg(args_node):
    """Return the unquoted text of the first string literal in a JS arguments node."""
    for child in args_node.children:
        if child.type == "string":
            return _strip_quotes(_node_text(child))
    return None

# ---------------------------------------------------------------------------
# Go analyser
# ---------------------------------------------------------------------------

def analyze_go_ast(filepath, content):
    """Detect suspicious patterns in Go source via Tree-sitter."""
    findings = []
    root = _parse(GO_LANGUAGE, content)

    if root is None:
        if GO_LANGUAGE is None:
            findings.append({
                "type": "AST Scanning Disabled",
                "file": filepath,
                "line": 0,
                "description": "tree-sitter-go grammar not installed. Go AST scanning skipped."
            })
        return findings

    for node in _walk(root):
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node is None:
                continue
            func_text = _node_text(func_node)

            # exec.Command() / os/exec.Command()
            if func_text in ("exec.Command", "exec.CommandContext"):
                findings.append({
                    "type": "System Command Execution",
                    "file": filepath,
                    "line": _line(node),
                    "description": f"Use of `{func_text}()` detected."
                })

            # os.Getenv() for sensitive keys
            if func_text == "os.Getenv" and args_node is not None:
                first_arg = _first_go_string_arg(args_node)
                if first_arg is not None and _matches_sensitive_key(first_arg):
                    findings.append({
                        "type": "Credential Theft",
                        "file": filepath,
                        "line": _line(node),
                        "description": f"Access to sensitive environment variable: `{first_arg}`"
                    })

            # net/http outbound calls: http.Get, http.Post, http.NewRequest
            if func_text in ("http.Get", "http.Post", "http.NewRequest"):
                findings.append({
                    "type": "Suspicious Network Call",
                    "file": filepath,
                    "line": _line(node),
                    "description": f"Use of `{func_text}()` detected. Verify the outbound destination."
                })

    return findings


def _first_go_string_arg(args_node):
    """Return the unquoted text of the first string literal in a Go argument_list."""
    for child in args_node.children:
        if child.type == "interpreted_string_literal" or child.type == "raw_string_literal":
            return _strip_quotes(_node_text(child))
    return None

# ---------------------------------------------------------------------------
# Ruby analyser
# ---------------------------------------------------------------------------

def analyze_ruby_ast(filepath, content):
    """Detect suspicious patterns in Ruby source via Tree-sitter."""
    findings = []
    root = _parse(RB_LANGUAGE, content)

    if root is None:
        if RB_LANGUAGE is None:
            findings.append({
                "type": "AST Scanning Disabled",
                "file": filepath,
                "line": 0,
                "description": "tree-sitter-ruby grammar not installed. Ruby AST scanning skipped."
            })
        return findings

    for node in _walk(root):
        # --- method calls: system(), exec(), IO.popen(), Open3.*, Kernel.exec
        if node.type == "call" or node.type == "method_call":
            method_node = node.child_by_field_name("method")
            receiver_node = node.child_by_field_name("receiver")

            if method_node is None:
                continue
            method_name = _node_text(method_node)
            receiver_name = _node_text(receiver_node) if receiver_node else ""

            # Bare system() / exec()
            if receiver_node is None and method_name in ("system", "exec"):
                findings.append({
                    "type": "System Command Execution",
                    "file": filepath,
                    "line": _line(node),
                    "description": f"Use of `{method_name}()` detected."
                })

            # Kernel.exec, Kernel.system
            if receiver_name == "Kernel" and method_name in ("exec", "system"):
                findings.append({
                    "type": "System Command Execution",
                    "file": filepath,
                    "line": _line(node),
                    "description": f"Use of `Kernel.{method_name}()` detected."
                })

            # IO.popen
            if receiver_name == "IO" and method_name == "popen":
                findings.append({
                    "type": "System Command Execution",
                    "file": filepath,
                    "line": _line(node),
                    "description": "Use of `IO.popen()` detected."
                })

            # Open3.*
            if receiver_name == "Open3" and method_name in ("popen3", "popen2", "capture3", "capture2", "pipeline"):
                findings.append({
                    "type": "System Command Execution",
                    "file": filepath,
                    "line": _line(node),
                    "description": f"Use of `Open3.{method_name}()` detected."
                })

        # --- backtick (subshell) commands ------------------------------------
        if node.type == "subshell":
            findings.append({
                "type": "System Command Execution",
                "file": filepath,
                "line": _line(node),
                "description": "Use of backtick subshell command detected."
            })

        # --- ENV['KEY'] access -----------------------------------------------
        if node.type == "element_reference":
            obj_node = node.child_by_field_name("object")
            if obj_node is not None and _node_text(obj_node) == "ENV":
                # The key is usually the second child (after '[')
                for child in node.children:
                    if child.type == "string":
                        key = _strip_quotes(_node_text(child))
                        if _matches_sensitive_key(key):
                            findings.append({
                                "type": "Credential Theft",
                                "file": filepath,
                                "line": _line(node),
                                "description": f"Access to sensitive environment variable: `{key}`"
                            })
                        break

    return findings

# ---------------------------------------------------------------------------
# package.json analyser (kept exactly as-is -- uses JSON, not AST)
# ---------------------------------------------------------------------------

def analyze_package_json(filepath, content):
    """
    Parses package.json to find suspicious lifecycle scripts.
    """
    findings = []
    try:
        pkg_data = json.loads(content)
    except json.JSONDecodeError as e:
        findings.append({
            "type": "JSON Parsing Error",
            "file": filepath,
            "line": 0,
            "description": f"Failed to parse package.json: {e.msg}"
        })
        return findings

    scripts = pkg_data.get("scripts", {})
    lifecycle_hooks = ["preinstall", "install", "postinstall", "preuninstall", "uninstall", "postuninstall"]

    suspicious_commands = ["bun ", "curl ", "wget ", "powershell", "cmd.exe", "/bin/sh", "/bin/bash"]

    for hook in lifecycle_hooks:
        if hook in scripts:
            script_content = scripts[hook]

            for cmd in suspicious_commands:
                if cmd in script_content.lower():
                    findings.append({
                        "type": "Suspicious Lifecycle Script",
                        "file": filepath,
                        "line": 0,  # Difficult to get exact line number from parsed JSON
                        "description": f"The `{hook}` script uses suspicious command `{cmd}`: {script_content}"
                    })

    return findings

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

def scan_file_ast(filepath, content):
    """
    Router function to scan file content based on extension.
    """
    ext = os.path.splitext(filepath)[1].lower()

    if ext == '.py':
        return analyze_python_ast(filepath, content)
    elif ext in ('.js', '.mjs', '.cjs'):
        return analyze_javascript_ast(filepath, content)
    elif ext == '.go':
        return analyze_go_ast(filepath, content)
    elif ext == '.rb':
        return analyze_ruby_ast(filepath, content)
    elif os.path.basename(filepath) == 'package.json':
        return analyze_package_json(filepath, content)

    return []
