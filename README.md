# ⚒ YaraForge

**YARA Rule Generator & Testing Platform**

A Flask-based platform for building, managing, testing, and visualizing YARA rules — with MITRE ATT&CK mapping and a detection dashboard.

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask)
![YARA](https://img.shields.io/badge/YARA-4.5-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

### Rule Builder
- **Guided mode** — form-based string/condition builder that generates valid YARA syntax
- **Raw editor** — full YARA syntax editor with real-time validation
- **MITRE ATT&CK mapping** — tag rules with technique IDs for coverage tracking
- **Metadata management** — severity levels, categories, tags, and author attribution

### Rule Manager
- Search, filter, and organize rules by category and severity
- Toggle rules active/inactive for selective scanning
- Version history tracking for rule changes
- Inline edit and delete with confirmation

### File Scanner
- Drag-and-drop file upload for scanning
- Scan against all active YARA rules simultaneously
- Detailed match results with string offsets and hex data
- Scan history with performance metrics

### Detection Dashboard
- Overview statistics: total rules, scans, matches, MITRE coverage
- Category distribution and severity breakdown charts
- MITRE ATT&CK technique coverage heat map
- Recent scan history table

### Import / Export
- Import `.yar` files with automatic rule parsing and validation
- Export selected or all rules to a single `.yar` file
- Duplicate detection during import

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.9+, Flask 3.0 |
| YARA Engine | yara-python 4.5 |
| Database | SQLite (WAL mode) |
| Frontend | HTML5, CSS3, Vanilla JS |
| Charts | Canvas 2D API |

---

## Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Step-by-Step Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/YaraForge.git
   cd YaraForge
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv

   # Windows
   venv\Scripts\activate

   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

   > **Note:** On some systems, `yara-python` may require C compilation tools.
   > - **Windows:** Install [Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   > - **Linux:** `sudo apt install build-essential libssl-dev`
   > - **Alternative:** `pip install yara-python-dex` (pre-compiled wheels)

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Open in browser**
   ```
   http://127.0.0.1:5000
   ```

---

## Quick Start

1. **Import sample rules** — Go to Import/Export and upload `sample_rules/starter_rules.yar`
2. **Create a rule** — Use the Rule Builder to create custom detection rules
3. **Scan a file** — Upload any file in the Scanner to test against your rules
4. **Review dashboard** — Check your detection coverage on the Dashboard

---

## Project Structure

```
YaraForge/
├── app.py                 # Flask application & API routes
├── database.py            # SQLite database operations
├── yara_engine.py         # YARA compilation, validation & scanning
├── requirements.txt       # Python dependencies
├── static/
│   ├── css/style.css      # Dark cyber theme stylesheet
│   └── js/app.js          # Frontend application logic
├── templates/
│   ├── base.html          # Base layout with navigation
│   ├── dashboard.html     # Statistics & MITRE coverage
│   ├── builder.html       # Rule creation interface
│   ├── manager.html       # Rule management table
│   ├── tester.html        # File scanner interface
│   └── import_export.html # Import/export interface
├── sample_rules/
│   └── starter_rules.yar  # 6 pre-built detection rules
├── rules/                 # Stored rule files
├── uploads/               # Temporary scan uploads
└── README.md
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/rules` | Create a new rule |
| PUT | `/api/rules/<id>` | Update an existing rule |
| DELETE | `/api/rules/<id>` | Delete a rule |
| POST | `/api/rules/<id>/toggle` | Toggle rule active status |
| GET | `/api/rules/<id>/versions` | Get rule version history |
| POST | `/api/validate` | Validate YARA rule syntax |
| POST | `/api/generate` | Generate rule from parameters |
| POST | `/api/scan` | Scan a file against active rules |
| POST | `/api/import` | Import rules from .yar file |
| POST | `/api/export` | Export rules to .yar file |
| GET | `/api/stats` | Get dashboard statistics |

---

## Sample Rules Included

| Rule | Category | Severity | MITRE |
|------|----------|----------|-------|
| `detect_mimikatz` | Infostealer | Critical | T1003 |
| `detect_powershell_encoded_command` | Exploit | High | T1059.001 |
| `detect_ransomware_indicators` | Ransomware | Critical | T1486 |
| `detect_webshell_generic` | Webshell | High | T1505.003 |
| `detect_pe_file` | Custom | Info | — |
| `detect_reverse_shell_strings` | Backdoor | High | T1059 |

---

## Security Considerations

- Uploaded files are scanned in a temporary directory and **deleted immediately** after scanning
- File uploads are limited to 50MB
- The application runs on `127.0.0.1` (localhost only) by default
- No authentication is included — intended for local/lab use
- **Do not expose to the public internet without adding authentication**

---

## Skills Demonstrated

- **Python Backend Development** — Flask API design, SQLite ORM operations, file handling
- **YARA Rule Engineering** — Rule syntax, compilation, string matching, condition logic
- **MITRE ATT&CK Framework** — Technique mapping, tactic categorization, coverage analysis
- **Detection Engineering** — Building detection signatures, testing against samples
- **Web Application Security** — Input validation, secure file handling, CSRF considerations
- **Frontend Development** — Responsive dark theme UI, Canvas 2D charts, drag-and-drop

---

## Future Enhancements

- [ ] User authentication and role-based access
- [ ] YARA rule auto-generation from malware samples
- [ ] VirusTotal API integration for hash lookups
- [ ] Rule sharing / community repository
- [ ] Automated rule testing with CI/CD pipeline
- [ ] Docker containerization for easy deployment

---

## License

MIT License

---

## Author

Built as a cybersecurity portfolio project demonstrating detection engineering, YARA rule development, and full-stack web application skills.
