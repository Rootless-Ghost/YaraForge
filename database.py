"""
YaraForge - Database Module
Handles SQLite database operations for YARA rules and scan results.
"""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yaraforge.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            category TEXT DEFAULT 'uncategorized',
            author TEXT DEFAULT 'YaraForge User',
            rule_content TEXT NOT NULL,
            mitre_techniques TEXT DEFAULT '[]',
            tags TEXT DEFAULT '[]',
            severity TEXT DEFAULT 'medium',
            date_created TEXT NOT NULL,
            date_modified TEXT NOT NULL,
            version INTEGER DEFAULT 1,
            is_active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            file_hash TEXT DEFAULT '',
            scan_date TEXT NOT NULL,
            total_rules_scanned INTEGER DEFAULT 0,
            matches_found INTEGER DEFAULT 0,
            match_details TEXT DEFAULT '[]',
            scan_duration_ms REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS rule_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER NOT NULL,
            version INTEGER NOT NULL,
            rule_content TEXT NOT NULL,
            change_note TEXT DEFAULT '',
            date_created TEXT NOT NULL,
            FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()


def create_rule(name, description, category, author, rule_content,
                mitre_techniques=None, tags=None, severity="medium"):
    conn = get_db()
    now = datetime.now().isoformat()
    try:
        conn.execute("""
            INSERT INTO rules (name, description, category, author, rule_content,
                             mitre_techniques, tags, severity, date_created, date_modified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, description, category, author, rule_content,
              json.dumps(mitre_techniques or []), json.dumps(tags or []),
              severity, now, now))
        conn.commit()
        rule_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("""
            INSERT INTO rule_versions (rule_id, version, rule_content, change_note, date_created)
            VALUES (?, 1, ?, 'Initial creation', ?)
        """, (rule_id, rule_content, now))
        conn.commit()
        return rule_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_all_rules():
    conn = get_db()
    rules = conn.execute("SELECT * FROM rules ORDER BY date_modified DESC").fetchall()
    conn.close()
    return [dict(r) for r in rules]


def get_rule_by_id(rule_id):
    conn = get_db()
    rule = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    conn.close()
    return dict(rule) if rule else None


def get_active_rules():
    conn = get_db()
    rules = conn.execute("SELECT * FROM rules WHERE is_active = 1 ORDER BY date_modified DESC").fetchall()
    conn.close()
    return [dict(r) for r in rules]


def update_rule(rule_id, **kwargs):
    conn = get_db()
    rule = get_rule_by_id(rule_id)
    if not rule:
        conn.close()
        return False
    # Only allow updates to known, safe columns
    allowed_fields = {
        "name",
        "description",
        "category",
        "author",
        "rule_content",
        "mitre_techniques",
        "tags",
        "severity",
        "is_active",
        "date_modified",
        "version",
    }
    kwargs["date_modified"] = datetime.now().isoformat()
    if "mitre_techniques" in kwargs and isinstance(kwargs["mitre_techniques"], list):
        kwargs["mitre_techniques"] = json.dumps(kwargs["mitre_techniques"])
    if "tags" in kwargs and isinstance(kwargs["tags"], list):
        kwargs["tags"] = json.dumps(kwargs["tags"])
    if "rule_content" in kwargs and kwargs["rule_content"] != rule["rule_content"]:
        new_version = rule["version"] + 1
        kwargs["version"] = new_version
        conn.execute("""
            INSERT INTO rule_versions (rule_id, version, rule_content, change_note, date_created)
            VALUES (?, ?, ?, ?, ?)
        """, (rule_id, new_version, kwargs["rule_content"],
              kwargs.pop("change_note", "Updated"), kwargs["date_modified"]))
    # Filter to allowed fields to avoid SQL injection via column names
    sanitized_kwargs = {k: v for k, v in kwargs.items() if k in allowed_fields}
    if not sanitized_kwargs:
        conn.close()
        return True
    set_clause = ", ".join(f"{k} = ?" for k in sanitized_kwargs)
    values = list(sanitized_kwargs.values()) + [rule_id]
    conn.execute(f"UPDATE rules SET {set_clause} WHERE id = ?", values)
    conn.commit()
    conn.close()
    return True


def delete_rule(rule_id):
    conn = get_db()
    conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


def toggle_rule(rule_id):
    conn = get_db()
    rule = conn.execute("SELECT is_active FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if rule:
        new_status = 0 if rule["is_active"] else 1
        conn.execute("UPDATE rules SET is_active = ? WHERE id = ?", (new_status, rule_id))
        conn.commit()
    conn.close()


def save_scan_result(filename, file_size, file_hash, total_rules,
                     matches_found, match_details, duration_ms):
    conn = get_db()
    now = datetime.now().isoformat()
    conn.execute("""
        INSERT INTO scan_results (filename, file_size, file_hash, scan_date,
                                 total_rules_scanned, matches_found, match_details, scan_duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (filename, file_size, file_hash, now, total_rules,
          matches_found, json.dumps(match_details), duration_ms))
    conn.commit()
    conn.close()


def get_scan_results(limit=50):
    conn = get_db()
    results = conn.execute("SELECT * FROM scan_results ORDER BY scan_date DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in results]


def get_dashboard_stats():
    conn = get_db()
    stats = {}
    stats["total_rules"] = conn.execute("SELECT COUNT(*) as c FROM rules").fetchone()["c"]
    stats["active_rules"] = conn.execute("SELECT COUNT(*) as c FROM rules WHERE is_active = 1").fetchone()["c"]
    categories = conn.execute("SELECT category, COUNT(*) as count FROM rules GROUP BY category ORDER BY count DESC").fetchall()
    stats["categories"] = {r["category"]: r["count"] for r in categories}
    severities = conn.execute("SELECT severity, COUNT(*) as count FROM rules GROUP BY severity").fetchall()
    stats["severities"] = {r["severity"]: r["count"] for r in severities}
    stats["total_scans"] = conn.execute("SELECT COUNT(*) as c FROM scan_results").fetchone()["c"]
    row = conn.execute("SELECT SUM(matches_found) as total FROM scan_results").fetchone()
    stats["total_matches"] = row["total"] or 0
    recent = conn.execute("SELECT * FROM scan_results ORDER BY scan_date DESC LIMIT 10").fetchall()
    stats["recent_scans"] = [dict(r) for r in recent]
    rules = conn.execute("SELECT mitre_techniques FROM rules WHERE is_active = 1").fetchall()
    technique_counts = {}
    for r in rules:
        try:
            techniques = json.loads(r["mitre_techniques"])
            for t in techniques:
                technique_counts[t] = technique_counts.get(t, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass
    stats["mitre_coverage"] = technique_counts
    conn.close()
    return stats


def get_rule_versions(rule_id):
    conn = get_db()
    versions = conn.execute("SELECT * FROM rule_versions WHERE rule_id = ? ORDER BY version DESC", (rule_id,)).fetchall()
    conn.close()
    return [dict(v) for v in versions]
