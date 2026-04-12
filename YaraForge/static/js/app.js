/* ═══════════════════════════════════════════════════════
   YaraForge — Frontend Application Logic
   ═══════════════════════════════════════════════════════ */

// ── Toast Notifications ─────────────────────────────────

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icons = { success: '✓', error: '✕', info: 'ℹ' };
    toast.innerHTML = `<span>${icons[type] || 'ℹ'}</span> ${message}`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}


// ── Tab Switching ────────────────────────────────────────

function initTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const group = tab.closest('.tabs');
            const parent = group.parentElement;

            group.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            parent.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
            const target = document.getElementById(tab.dataset.tab);
            if (target) target.classList.add('active');
        });
    });
}


// ── Rule Builder: String Management ──────────────────────

let stringCounter = 0;

function addStringRow() {
    const container = document.getElementById('strings-container');
    if (!container) return;

    stringCounter++;
    const row = document.createElement('div');
    row.className = 'string-row';
    row.id = `string-row-${stringCounter}`;
    row.innerHTML = `
        <input type="text" class="form-input" placeholder="$name" value="$s${stringCounter}" data-field="name">
        <select class="form-select" data-field="type">
            <option value="text">Text</option>
            <option value="hex">Hex</option>
            <option value="regex">Regex</option>
        </select>
        <input type="text" class="form-input" placeholder="Enter value..." data-field="value">
        <button class="btn btn-danger btn-sm" onclick="removeStringRow(${stringCounter})">✕</button>
    `;
    container.appendChild(row);
}

function removeStringRow(id) {
    const row = document.getElementById(`string-row-${id}`);
    if (row) row.remove();
}

function getStrings() {
    const strings = [];
    document.querySelectorAll('.string-row').forEach(row => {
        const name = row.querySelector('[data-field="name"]').value;
        const type = row.querySelector('[data-field="type"]').value;
        const value = row.querySelector('[data-field="value"]').value;
        if (value.trim()) {
            strings.push({ name: name.replace('$', ''), type, value });
        }
    });
    return strings;
}


// ── Rule Builder: Generate Rule ──────────────────────────

async function generateRule() {
    const name = document.getElementById('rule-name')?.value || 'unnamed_rule';
    const description = document.getElementById('rule-description')?.value || '';
    const author = document.getElementById('rule-author')?.value || 'YaraForge User';
    const category = document.getElementById('rule-category')?.value || 'uncategorized';
    const condition = document.getElementById('rule-condition')?.value || 'any of them';
    const strings = getStrings();

    try {
        const resp = await fetch('/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, description, author, category, strings, condition })
        });
        const data = await resp.json();

        const editor = document.getElementById('raw-editor');
        if (editor) {
            editor.value = data.rule_content;
        }

        // Switch to raw editor tab
        document.querySelector('[data-tab="tab-raw"]')?.click();

        if (data.valid) {
            showToast('Rule generated and validated successfully!', 'success');
            updateValidationStatus(true);
        } else {
            showToast(`Generated but has errors: ${data.error}`, 'error');
            updateValidationStatus(false, data.error);
        }
    } catch (err) {
        showToast('Failed to generate rule', 'error');
    }
}


// ── Rule Validation ──────────────────────────────────────

async function validateRule() {
    const editor = document.getElementById('raw-editor');
    if (!editor || !editor.value.trim()) {
        showToast('No rule content to validate', 'error');
        return;
    }

    try {
        const resp = await fetch('/api/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_content: editor.value })
        });
        const data = await resp.json();

        if (data.valid) {
            showToast('Rule is valid!', 'success');
            updateValidationStatus(true);
        } else {
            showToast(`Validation failed: ${data.error}`, 'error');
            updateValidationStatus(false, data.error);
        }
    } catch (err) {
        showToast('Validation request failed', 'error');
    }
}

function updateValidationStatus(valid, error = '') {
    const status = document.getElementById('validation-status');
    if (!status) return;

    if (valid) {
        status.innerHTML = '<span class="badge badge-green">✓ Valid YARA Rule</span>';
    } else {
        status.innerHTML = `<span class="badge badge-red">✕ Invalid: ${error}</span>`;
    }
}


// ── Save Rule ────────────────────────────────────────────

async function saveRule(editId = null) {
    const editor = document.getElementById('raw-editor');
    const name = document.getElementById('rule-name')?.value?.trim();
    const ruleContent = editor?.value?.trim();

    if (!name) {
        showToast('Please enter a rule name', 'error');
        return;
    }
    if (!ruleContent) {
        showToast('No rule content to save', 'error');
        return;
    }

    const data = {
        name: name,
        description: document.getElementById('rule-description')?.value || '',
        category: document.getElementById('rule-category')?.value || 'uncategorized',
        author: document.getElementById('rule-author')?.value || 'YaraForge User',
        severity: document.getElementById('rule-severity')?.value || 'medium',
        rule_content: ruleContent,
        mitre_techniques: getSelectedMitre(),
        tags: getTagsInput()
    };

    try {
        let resp;
        if (editId) {
            resp = await fetch(`/api/rules/${editId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
        } else {
            resp = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
        }

        const result = await resp.json();

        if (resp.ok) {
            showToast(editId ? 'Rule updated!' : 'Rule saved!', 'success');
            setTimeout(() => window.location.href = '/manager', 1000);
        } else {
            showToast(result.error || 'Failed to save rule', 'error');
        }
    } catch (err) {
        showToast('Failed to save rule', 'error');
    }
}

function getSelectedMitre() {
    const checkboxes = document.querySelectorAll('.mitre-checkbox:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

function getTagsInput() {
    const input = document.getElementById('rule-tags');
    if (!input || !input.value.trim()) return [];
    return input.value.split(',').map(t => t.trim()).filter(Boolean);
}


// ── Rule Manager: Actions ────────────────────────────────

async function deleteRule(id, name) {
    if (!confirm(`Delete rule "${name}"? This cannot be undone.`)) return;

    try {
        const resp = await fetch(`/api/rules/${id}`, { method: 'DELETE' });
        if (resp.ok) {
            showToast(`Rule "${name}" deleted`, 'success');
            document.getElementById(`rule-row-${id}`)?.remove();
        }
    } catch (err) {
        showToast('Failed to delete rule', 'error');
    }
}

async function toggleRuleActive(id) {
    try {
        await fetch(`/api/rules/${id}/toggle`, { method: 'POST' });
    } catch (err) {
        showToast('Failed to toggle rule', 'error');
    }
}


// ── File Scanner ─────────────────────────────────────────

function initScanner() {
    const zone = document.getElementById('upload-zone');
    const input = document.getElementById('scan-file-input');
    if (!zone || !input) return;

    zone.addEventListener('click', () => input.click());

    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', () => {
        zone.classList.remove('dragover');
    });

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            input.files = e.dataTransfer.files;
            scanFile();
        }
    });

    input.addEventListener('change', () => {
        if (input.files.length) scanFile();
    });
}

async function scanFile() {
    const input = document.getElementById('scan-file-input');
    if (!input?.files?.length) {
        showToast('No file selected', 'error');
        return;
    }

    const file = input.files[0];
    const resultsDiv = document.getElementById('scan-results');
    const loadingDiv = document.getElementById('scan-loading');

    if (loadingDiv) loadingDiv.classList.remove('hidden');
    if (resultsDiv) resultsDiv.innerHTML = '';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const resp = await fetch('/api/scan', { method: 'POST', body: formData });
        const data = await resp.json();

        if (loadingDiv) loadingDiv.classList.add('hidden');

        if (!resp.ok) {
            showToast(data.error || 'Scan failed', 'error');
            return;
        }

        renderScanResults(data, resultsDiv);

    } catch (err) {
        if (loadingDiv) loadingDiv.classList.add('hidden');
        showToast('Scan request failed', 'error');
    }
}

function renderScanResults(data, container) {
    if (!container) return;

    const matchClass = data.matches_found > 0 ? 'text-red' : 'text-green';
    const matchIcon = data.matches_found > 0 ? '⚠' : '✓';

    let html = `
        <div class="scan-result">
            <div class="scan-result-header">
                <div>
                    <strong class="text-mono">${data.filename || 'Unknown'}</strong>
                    <span class="text-muted text-sm" style="margin-left: 12px;">
                        ${formatBytes(data.file_size)} · SHA-256: ${(data.file_hash || '').substring(0, 16)}...
                    </span>
                </div>
                <div>
                    <span class="${matchClass}" style="font-weight: 600;">
                        ${matchIcon} ${data.matches_found} match${data.matches_found !== 1 ? 'es' : ''}
                    </span>
                    <span class="text-muted text-sm" style="margin-left: 12px;">
                        ${data.total_rules_scanned} rules · ${data.duration_ms}ms
                    </span>
                </div>
            </div>
            <div class="scan-result-body">
    `;

    if (data.matches_found > 0 && data.match_details) {
        data.match_details.forEach(match => {
            html += `
                <div class="match-item severity-${match.severity}">
                    <div class="flex justify-between items-center mb-4">
                        <strong class="text-mono">${match.rule_name}</strong>
                        <div class="tag-list">
                            <span class="badge badge-${getSeverityColor(match.severity)}">${match.severity}</span>
                            <span class="badge badge-muted">${match.category}</span>
                        </div>
                    </div>
            `;

            if (match.strings && match.strings.length > 0) {
                html += '<div class="text-sm text-muted mt-4">Matched strings:</div>';
                match.strings.forEach(s => {
                    html += `<div class="text-mono text-sm" style="margin-top:4px; color: var(--accent-amber);">
                        ${s.identifier} @ offset ${s.offset} (${s.length} bytes)
                    </div>`;
                });
            }

            html += '</div>';
        });
    } else {
        html += '<div class="no-matches">✓ No detections — file is clean against all active rules</div>';
    }

    if (data.compile_errors && data.compile_errors.length > 0) {
        html += '<div class="mt-4 text-sm text-muted"><strong>Compile warnings:</strong></div>';
        data.compile_errors.forEach(err => {
            html += `<div class="text-sm text-red">${err}</div>`;
        });
    }

    html += '</div></div>';
    container.innerHTML = html;
}


// ── Import / Export ──────────────────────────────────────

function initImport() {
    const zone = document.getElementById('import-zone');
    const input = document.getElementById('import-file-input');
    if (!zone || !input) return;

    zone.addEventListener('click', () => input.click());

    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            input.files = e.dataTransfer.files;
            importRules();
        }
    });

    input.addEventListener('change', () => {
        if (input.files.length) importRules();
    });
}

async function importRules() {
    const input = document.getElementById('import-file-input');
    if (!input?.files?.length) return;

    const formData = new FormData();
    formData.append('file', input.files[0]);

    try {
        const resp = await fetch('/api/import', { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.imported > 0) {
            showToast(`Imported ${data.imported} of ${data.total_found} rules`, 'success');
        }
        if (data.errors?.length) {
            data.errors.forEach(e => showToast(e, 'error'));
        }

        setTimeout(() => window.location.reload(), 1500);
    } catch (err) {
        showToast('Import failed', 'error');
    }
}

async function exportRules(ruleIds = []) {
    try {
        const resp = await fetch('/api/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_ids: ruleIds })
        });

        if (resp.ok) {
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'yaraforge_rules.yar';
            a.click();
            URL.revokeObjectURL(url);
            showToast('Rules exported!', 'success');
        }
    } catch (err) {
        showToast('Export failed', 'error');
    }
}

function exportSelected() {
    const checked = document.querySelectorAll('.export-checkbox:checked');
    const ids = Array.from(checked).map(cb => parseInt(cb.value));
    exportRules(ids);
}


// ── MITRE Filter ─────────────────────────────────────────

function filterMitre() {
    const query = document.getElementById('mitre-search')?.value?.toLowerCase() || '';
    document.querySelectorAll('.multi-select-item').forEach(item => {
        const text = item.textContent.toLowerCase();
        item.style.display = text.includes(query) ? '' : 'none';
    });
}


// ── Utility Functions ────────────────────────────────────

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
}

function getSeverityColor(severity) {
    const map = { critical: 'red', high: 'amber', medium: 'blue', low: 'green', info: 'muted' };
    return map[severity] || 'muted';
}


// ── Manager Search/Filter ────────────────────────────────

function filterRules() {
    const query = (document.getElementById('rule-search')?.value || '').toLowerCase();
    const category = document.getElementById('filter-category')?.value || '';
    const severity = document.getElementById('filter-severity')?.value || '';

    document.querySelectorAll('[id^="rule-row-"]').forEach(row => {
        const name = (row.dataset.name || '').toLowerCase();
        const cat = row.dataset.category || '';
        const sev = row.dataset.severity || '';

        const matchName = !query || name.includes(query);
        const matchCat = !category || cat === category;
        const matchSev = !severity || sev === severity;

        row.style.display = (matchName && matchCat && matchSev) ? '' : 'none';
    });
}


// ── Dashboard Charts (using Canvas 2D) ───────────────────

function initDashboardCharts(stats) {
    if (!stats) return;

    drawCategoryChart(stats.categories || {});
    drawSeverityChart(stats.severities || {});
}

function drawCategoryChart(data) {
    const canvas = document.getElementById('category-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const entries = Object.entries(data);
    if (!entries.length) return;

    const colors = ['#64d9a5', '#5b9cf5', '#f5a623', '#a78bfa', '#f56565', '#8b90a5'];
    const total = entries.reduce((s, [, v]) => s + v, 0);
    const width = canvas.width = canvas.parentElement.clientWidth;
    const height = canvas.height = 220;
    const barHeight = 28;
    const padding = 20;
    const maxLabelWidth = 120;

    ctx.clearRect(0, 0, width, height);

    entries.slice(0, 6).forEach(([label, value], i) => {
        const y = padding + i * (barHeight + 10);
        const barWidth = ((width - maxLabelWidth - padding * 2) * value) / total;

        // Label
        ctx.fillStyle = '#8b90a5';
        ctx.font = '12px "Outfit", sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(label, maxLabelWidth - 10, y + barHeight / 2 + 4);

        // Bar background
        ctx.fillStyle = '#1e2235';
        ctx.beginPath();
        ctx.roundRect(maxLabelWidth, y, width - maxLabelWidth - padding, barHeight, 4);
        ctx.fill();

        // Bar fill
        ctx.fillStyle = colors[i % colors.length];
        ctx.beginPath();
        ctx.roundRect(maxLabelWidth, y, Math.max(barWidth, 4), barHeight, 4);
        ctx.fill();

        // Count
        ctx.fillStyle = '#e4e7ef';
        ctx.font = '600 12px "JetBrains Mono", monospace';
        ctx.textAlign = 'left';
        ctx.fillText(value, maxLabelWidth + barWidth + 8, y + barHeight / 2 + 4);
    });
}

function drawSeverityChart(data) {
    const canvas = document.getElementById('severity-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const colorMap = {
        critical: '#f56565', high: '#f5a623', medium: '#5b9cf5',
        low: '#64d9a5', info: '#8b90a5'
    };
    const total = Object.values(data).reduce((s, v) => s + v, 0);
    if (!total) return;

    const width = canvas.width = canvas.parentElement.clientWidth;
    const height = canvas.height = 220;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 2 - 30;

    ctx.clearRect(0, 0, width, height);

    let startAngle = -Math.PI / 2;
    order.forEach(sev => {
        const value = data[sev] || 0;
        if (!value) return;
        const sliceAngle = (value / total) * Math.PI * 2;

        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        ctx.closePath();
        ctx.fillStyle = colorMap[sev];
        ctx.fill();

        // Label
        const midAngle = startAngle + sliceAngle / 2;
        const labelX = centerX + (radius * 0.65) * Math.cos(midAngle);
        const labelY = centerY + (radius * 0.65) * Math.sin(midAngle);
        ctx.fillStyle = '#0a0c10';
        ctx.font = '600 12px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.fillText(value, labelX, labelY + 4);

        startAngle += sliceAngle;
    });

    // Center hole (donut)
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius * 0.45, 0, Math.PI * 2);
    ctx.fillStyle = '#161923';
    ctx.fill();

    // Center text
    ctx.fillStyle = '#e4e7ef';
    ctx.font = '700 22px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText(total, centerX, centerY + 4);
    ctx.font = '400 10px "Outfit", sans-serif';
    ctx.fillStyle = '#8b90a5';
    ctx.fillText('TOTAL', centerX, centerY + 18);
}


// ── Initialize ───────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initScanner();
    initImport();
});
