"""
YaraForge - YARA Engine Module
Handles YARA rule compilation, validation, and file scanning.
"""

import os
import time
import hashlib
import tempfile
import json

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[!] yara-python not installed. Install with: pip install yara-python")

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")


def validate_rule(rule_content):
    if not YARA_AVAILABLE:
        return False, "yara-python is not installed"
    try:
        yara.compile(source=rule_content)
        return True, None
    except yara.SyntaxError as e:
        return False, f"Syntax Error: {str(e)}"
    except yara.Error as e:
        return False, f"YARA Error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected Error: {str(e)}"


def compile_rules_from_db(rules):
    if not YARA_AVAILABLE:
        return None, ["yara-python is not installed"]
    errors = []
    sources = {}
    for rule in rules:
        try:
            yara.compile(source=rule["rule_content"])
            sources[f"rule_{rule['id']}"] = rule["rule_content"]
        except Exception as e:
            errors.append(f"Rule '{rule['name']}' (ID: {rule['id']}): {str(e)}")
    if not sources:
        return None, errors or ["No valid rules to compile"]
    try:
        compiled = yara.compile(sources=sources)
        return compiled, errors
    except Exception as e:
        return None, errors + [f"Compilation error: {str(e)}"]


def scan_file(file_path, rules):
    if not YARA_AVAILABLE:
        return {"success": False, "error": "yara-python is not installed", "matches": [], "duration_ms": 0}

    start_time = time.time()
    file_size = os.path.getsize(file_path)
    file_hash = _compute_hash(file_path)
    compiled, compile_errors = compile_rules_from_db(rules)

    if compiled is None:
        return {"success": False, "error": "No rules compiled successfully",
                "compile_errors": compile_errors, "matches": [], "duration_ms": 0}

    try:
        matches = compiled.match(file_path, timeout=30)
        duration_ms = (time.time() - start_time) * 1000
        match_details = []

        for match in matches:
            rule_id = None
            if match.namespace and match.namespace.startswith("rule_"):
                try:
                    rule_id = int(match.namespace.replace("rule_", ""))
                except ValueError:
                    pass

            rule_info = None
            if rule_id:
                for r in rules:
                    if r["id"] == rule_id:
                        rule_info = r
                        break

            match_detail = {
                "rule_name": match.rule,
                "rule_id": rule_id,
                "namespace": match.namespace,
                "tags": list(match.tags) if match.tags else [],
                "severity": rule_info["severity"] if rule_info else "unknown",
                "category": rule_info["category"] if rule_info else "unknown",
                "strings": []
            }

            for string_match in match.strings:
                for instance in string_match.instances:
                    match_detail["strings"].append({
                        "identifier": string_match.identifier,
                        "offset": instance.offset,
                        "length": instance.matched_length,
                        "data": instance.matched_data.hex()[:100]
                    })

            match_details.append(match_detail)

        return {
            "success": True,
            "filename": os.path.basename(file_path),
            "file_size": file_size,
            "file_hash": file_hash,
            "total_rules_scanned": len(rules),
            "matches_found": len(match_details),
            "match_details": match_details,
            "compile_errors": compile_errors,
            "duration_ms": round(duration_ms, 2)
        }
    except yara.TimeoutError:
        return {"success": False, "error": "Scan timed out (30s limit)", "matches": [], "duration_ms": 30000}
    except Exception as e:
        return {"success": False, "error": str(e), "matches": [], "duration_ms": (time.time() - start_time) * 1000}


def generate_rule_template(rule_name, description="", author="YaraForge User",
                            category="uncategorized", strings=None, condition="any of them"):
    safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in rule_name)
    meta_lines = [
        f'        description = "{description}"',
        f'        author = "{author}"',
        f'        category = "{category}"',
        f'        date = "{time.strftime("%Y-%m-%d")}"',
        f'        yaraforge_generated = true',
    ]
    string_lines = []
    if strings:
        for i, s in enumerate(strings):
            s_type = s.get("type", "text")
            s_value = s.get("value", "")
            s_name = s.get("name", f"s{i}")
            if not s_name.startswith("$"):
                s_name = f"${s_name}"
            if s_type == "text":
                string_lines.append(f'        {s_name} = "{s_value}"')
            elif s_type == "hex":
                string_lines.append(f'        {s_name} = {{ {s_value} }}')
            elif s_type == "regex":
                string_lines.append(f'        {s_name} = /{s_value}/')

    rule = f'rule {safe_name}\n{{\n'
    rule += '    meta:\n' + '\n'.join(meta_lines) + '\n\n'
    if string_lines:
        rule += '    strings:\n' + '\n'.join(string_lines) + '\n\n'
    rule += f'    condition:\n        {condition}\n}}'
    return rule


def export_rules(rules, output_path=None):
    header = f"/*\n    YaraForge Exported Rules\n    Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n    Total Rules: {len(rules)}\n*/\n\n"
    combined = header + "\n\n".join(r["rule_content"] for r in rules)
    if output_path:
        with open(output_path, "w") as f:
            f.write(combined)
    return combined


def import_rules_from_file(file_content):
    parsed_rules = []
    current_rule = []
    brace_depth = 0
    in_rule = False

    for line in file_content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("rule ") and not in_rule:
            in_rule = True
            current_rule = [line]
            if "{" in line:
                brace_depth += line.count("{") - line.count("}")
            continue
        if in_rule:
            current_rule.append(line)
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                rule_text = "\n".join(current_rule)
                name_line = current_rule[0].strip()
                name = name_line.replace("rule ", "").split("{")[0].split(":")[0].strip()
                description = _extract_meta(rule_text, "description")
                author = _extract_meta(rule_text, "author") or "Imported"
                category = _extract_meta(rule_text, "category") or "imported"
                parsed_rules.append({
                    "name": name, "description": description or f"Imported rule: {name}",
                    "author": author, "category": category, "rule_content": rule_text
                })
                in_rule = False
                current_rule = []
                brace_depth = 0
    return parsed_rules


def _extract_meta(rule_text, field):
    for line in rule_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith(f'{field}') and "=" in stripped:
            value = stripped.split("=", 1)[1].strip().strip('"').strip("'")
            return value
    return None


def _compute_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


MITRE_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1059.006": {"name": "Python", "tactic": "Execution"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1055.001": {"name": "DLL Injection", "tactic": "Defense Evasion"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    "T1204.002": {"name": "Malicious File", "tactic": "Execution"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1497": {"name": "Virtualization/Sandbox Evasion", "tactic": "Defense Evasion"},
}

MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact"
]
