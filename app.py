"""
YaraForge - YARA Rule Generator & Testing Platform
Main Flask Application
"""

import os
import json
import tempfile
from flask import (Flask, render_template, request, jsonify, redirect,
                   url_for, flash, send_file)
from werkzeug.utils import secure_filename
from database import (init_db, create_rule, get_all_rules, get_rule_by_id,
                      get_active_rules, update_rule, delete_rule, toggle_rule,
                      save_scan_result, get_scan_results, get_dashboard_stats,
                      get_rule_versions)
from yara_engine import (validate_rule, scan_file, generate_rule_template,
                         export_rules, import_rules_from_file,
                         MITRE_TECHNIQUES, MITRE_TACTICS, YARA_AVAILABLE)

app = Flask(__name__)
app.secret_key = os.urandom(32)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
RULES_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
MAX_UPLOAD_SIZE = 50 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RULES_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE


@app.route("/")
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats, page="dashboard")


@app.route("/builder")
def builder():
    rule_id = request.args.get("edit")
    rule = None
    if rule_id:
        rule = get_rule_by_id(int(rule_id))
        if rule:
            rule["mitre_techniques"] = json.loads(rule.get("mitre_techniques", "[]"))
            rule["tags"] = json.loads(rule.get("tags", "[]"))
    return render_template("builder.html", page="builder", rule=rule,
                         mitre_techniques=MITRE_TECHNIQUES, mitre_tactics=MITRE_TACTICS)


@app.route("/manager")
def manager():
    rules = get_all_rules()
    for r in rules:
        r["mitre_techniques"] = json.loads(r.get("mitre_techniques", "[]"))
        r["tags"] = json.loads(r.get("tags", "[]"))
    return render_template("manager.html", page="manager", rules=rules)


@app.route("/tester")
def tester():
    rules = get_active_rules()
    recent_scans = get_scan_results(limit=20)
    for scan in recent_scans:
        scan["match_details"] = json.loads(scan.get("match_details", "[]"))
    return render_template("tester.html", page="tester", rules=rules,
                         recent_scans=recent_scans, yara_available=YARA_AVAILABLE)


@app.route("/import-export")
def import_export():
    rules = get_all_rules()
    return render_template("import_export.html", page="import_export", rules=rules)


@app.route("/api/rules", methods=["POST"])
def api_create_rule():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    name = data.get("name", "").strip()
    rule_content = data.get("rule_content", "").strip()
    if not name or not rule_content:
        return jsonify({"error": "Name and rule content are required"}), 400
    is_valid, error = validate_rule(rule_content)
    if not is_valid:
        return jsonify({"error": f"Invalid YARA rule: {error}"}), 400
    rule_id = create_rule(
        name=name, description=data.get("description", ""),
        category=data.get("category", "uncategorized"),
        author=data.get("author", "YaraForge User"),
        rule_content=rule_content,
        mitre_techniques=data.get("mitre_techniques", []),
        tags=data.get("tags", []), severity=data.get("severity", "medium"))
    if rule_id is None:
        return jsonify({"error": f"A rule named '{name}' already exists"}), 409
    return jsonify({"success": True, "rule_id": rule_id}), 201


@app.route("/api/rules/<int:rule_id>", methods=["PUT"])
def api_update_rule(rule_id):
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    if "rule_content" in data:
        is_valid, error = validate_rule(data["rule_content"])
        if not is_valid:
            return jsonify({"error": f"Invalid YARA rule: {error}"}), 400
    success = update_rule(rule_id, **data)
    if not success:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify({"success": True})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    delete_rule(rule_id)
    return jsonify({"success": True})


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
def api_toggle_rule(rule_id):
    toggle_rule(rule_id)
    return jsonify({"success": True})


@app.route("/api/rules/<int:rule_id>/versions", methods=["GET"])
def api_rule_versions(rule_id):
    versions = get_rule_versions(rule_id)
    return jsonify({"versions": versions})


@app.route("/api/validate", methods=["POST"])
def api_validate_rule():
    data = request.get_json()
    rule_content = data.get("rule_content", "")
    is_valid, error = validate_rule(rule_content)
    return jsonify({"valid": is_valid, "error": error})


@app.route("/api/generate", methods=["POST"])
def api_generate_rule():
    data = request.get_json()
    rule_content = generate_rule_template(
        rule_name=data.get("name", "unnamed_rule"),
        description=data.get("description", ""),
        author=data.get("author", "YaraForge User"),
        category=data.get("category", "uncategorized"),
        strings=data.get("strings", []),
        condition=data.get("condition", "any of them"))
    is_valid, error = validate_rule(rule_content)
    return jsonify({"rule_content": rule_content, "valid": is_valid, "error": error})


@app.route("/api/scan", methods=["POST"])
def api_scan_file():
    if not YARA_AVAILABLE:
        return jsonify({"error": "yara-python is not installed on the server"}), 503
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)
    try:
        rules = get_active_rules()
        if not rules:
            return jsonify({"error": "No active rules to scan against"}), 400
        result = scan_file(filepath, rules)
        if result["success"]:
            save_scan_result(
                filename=result["filename"], file_size=result["file_size"],
                file_hash=result["file_hash"], total_rules=result["total_rules_scanned"],
                matches_found=result["matches_found"],
                match_details=result["match_details"], duration_ms=result["duration_ms"])
        return jsonify(result)
    finally:
        if os.path.exists(filepath):
            os.unlink(filepath)


@app.route("/api/import", methods=["POST"])
def api_import_rules():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    try:
        content = file.read().decode("utf-8")
    except UnicodeDecodeError:
        return jsonify({"error": "File must be a valid text/YARA file"}), 400
    parsed_rules = import_rules_from_file(content)
    if not parsed_rules:
        return jsonify({"error": "No valid YARA rules found in file"}), 400
    imported = 0
    errors = []
    for rule in parsed_rules:
        is_valid, error = validate_rule(rule["rule_content"])
        if not is_valid:
            errors.append(f"Rule '{rule['name']}': {error}")
            continue
        rule_id = create_rule(name=rule["name"], description=rule["description"],
                              category=rule["category"], author=rule["author"],
                              rule_content=rule["rule_content"])
        if rule_id:
            imported += 1
        else:
            errors.append(f"Rule '{rule['name']}': already exists")
    return jsonify({"success": True, "imported": imported,
                    "total_found": len(parsed_rules), "errors": errors})


@app.route("/api/export", methods=["POST"])
def api_export_rules():
    data = request.get_json()
    rule_ids = data.get("rule_ids", [])
    if not rule_ids:
        rules = get_all_rules()
    else:
        rules = [get_rule_by_id(rid) for rid in rule_ids if get_rule_by_id(rid)]
    if not rules:
        return jsonify({"error": "No rules to export"}), 400
    content = export_rules(rules)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False, dir=UPLOAD_FOLDER) as f:
        f.write(content)
        tmp_path = f.name
    return send_file(tmp_path, as_attachment=True, download_name="yaraforge_rules.yar", mimetype="text/plain")


@app.route("/api/stats", methods=["GET"])
def api_stats():
    stats = get_dashboard_stats()
    return jsonify(stats)


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large. Maximum size is 50MB."}), 413


if __name__ == "__main__":
    init_db()
    print("""
    ╔═══════════════════════════════════════════════╗
    ║         YaraForge v1.0 - Starting Up          ║
    ║   YARA Rule Generator & Testing Platform      ║
    ╠═══════════════════════════════════════════════╣
    ║  Dashboard:   http://127.0.0.1:5000           ║
    ╚═══════════════════════════════════════════════╝
    """)
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)
