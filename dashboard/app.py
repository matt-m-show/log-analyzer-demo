# Flask dashboard: serves alert data from logs/alerts.json over a local web API

import hashlib
import json
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

_ROOT         = Path(__file__).parent.parent
_ALERT_LOG    = _ROOT / "logs" / "alerts.json"
_STATUS_FILE  = _ROOT / "logs" / "alert_status.json"

_VALID_STATUSES = {"new", "in_progress", "resolved", "resolved_no_action"}

# ── Dashboard HTML ────────────────────────────────────────────────────────────

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Workspace Security Monitor</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:       #0d1117;
      --surface:  #161b22;
      --border:   #30363d;
      --text:     #c9d1d9;
      --muted:    #8b949e;
      --high:     #f85149;
      --medium:   #d29922;
      --low:      #58a6ff;
      --green:    #3fb950;
      --radius:   6px;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
    }

    /* ── Header ── */
    header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: .9rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      position: sticky;
      top: 0;
      z-index: 10;
    }
    header h1 {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: .5rem;
    }
    header h1::before { content: "🛡"; font-size: 1rem; }
    .header-meta {
      display: flex;
      align-items: center;
      gap: 1.25rem;
      color: var(--muted);
      font-size: .8rem;
    }
    #last-updated::before { content: "Updated: "; }
    #countdown { color: var(--low); font-variant-numeric: tabular-nums; }
    #countdown::before { content: "Next refresh: "; color: var(--muted); }

    /* ── Main layout ── */
    main { padding: 1.25rem 1.5rem; max-width: 1400px; margin: 0 auto; }

    /* ── Stat cards ── */
    .stat-bar {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: .75rem;
      margin-bottom: 1.25rem;
    }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: .9rem 1rem;
      display: flex;
      flex-direction: column;
      gap: .25rem;
    }
    .stat-card .label {
      font-size: .7rem;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--muted);
    }
    .stat-card .value {
      font-size: 1.7rem;
      font-weight: 700;
      line-height: 1;
    }
    .stat-total  .value { color: var(--text); }
    .stat-high   .value { color: var(--high); }
    .stat-medium .value { color: var(--medium); }
    .stat-low    .value { color: var(--low); }

    /* ── Filter bar ── */
    .filter-bar {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: .75rem 1rem;
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: .6rem;
      margin-bottom: 1rem;
    }
    .filter-bar label {
      font-size: .75rem;
      color: var(--muted);
      display: flex;
      flex-direction: column;
      gap: .2rem;
    }
    select, input[type="text"] {
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: .3rem .5rem;
      font-size: .85rem;
      outline: none;
    }
    select:focus, input:focus { border-color: var(--low); }
    input[type="text"] { width: 220px; }
    .filter-actions { display: flex; gap: .5rem; margin-left: auto; }
    button {
      border: none;
      border-radius: 4px;
      padding: .35rem .85rem;
      font-size: .8rem;
      cursor: pointer;
      font-weight: 500;
      transition: opacity .15s;
    }
    button:hover { opacity: .85; }
    .btn-primary   { background: #1f6feb; color: #fff; }
    .btn-secondary { background: var(--border); color: var(--text); }

    /* ── Alert cards ── */
    #alert-list { display: flex; flex-direction: column; gap: .6rem; }

    .alert-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-left-width: 4px;
      border-radius: var(--radius);
      overflow: hidden;
      transition: border-color .15s, opacity .6s;
    }
    .alert-card.high   { border-left-color: var(--high); }
    .alert-card.medium { border-left-color: var(--medium); }
    .alert-card.low    { border-left-color: var(--low); }
    .alert-card.fading { opacity: 0; }

    .card-header {
      display: flex;
      align-items: center;
      gap: .75rem;
      padding: .7rem 1rem;
      cursor: pointer;
    }
    .badge {
      font-size: .65rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .07em;
      padding: .15rem .45rem;
      border-radius: 3px;
      flex-shrink: 0;
    }
    .badge-high   { background: rgba(248,81,73,.18); color: var(--high); }
    .badge-medium { background: rgba(210,153,34,.18); color: var(--medium); }
    .badge-low    { background: rgba(88,166,255,.18); color: var(--low); }

    /* Description: full-width, monospace, wraps at 120 chars visually */
    .card-desc {
      flex: 1;
      font-family: monospace;
      font-size: .82rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 120ch;
    }

    .card-meta {
      display: flex;
      align-items: center;
      gap: .75rem;
      font-size: .75rem;
      color: var(--muted);
      flex-shrink: 0;
    }
    .card-meta span { white-space: nowrap; }

    /* Status dropdown in card header */
    .status-select {
      font-size: .72rem;
      padding: .15rem .35rem;
      border-radius: 3px;
      border: 1px solid var(--border);
      cursor: pointer;
      font-weight: 500;
      flex-shrink: 0;
    }
    .status-select.new               { color: var(--muted);  background: var(--bg); }
    .status-select.in_progress       { color: #d29922;        background: rgba(210,153,34,.12); }
    .status-select.resolved          { color: var(--green);   background: rgba(63,185,80,.12); }
    .status-select.resolved_no_action{ color: var(--low);     background: rgba(88,166,255,.12); }

    .expand-icon {
      font-size: .7rem;
      color: var(--muted);
      flex-shrink: 0;
      transition: transform .2s;
    }
    .alert-card.open .expand-icon { transform: rotate(180deg); }

    /* ── Expanded detail ── */
    .card-detail {
      display: none;
      padding: 0 1rem 1rem;
      border-top: 1px solid var(--border);
    }
    .alert-card.open .card-detail { display: block; }

    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: .4rem .8rem;
      padding: .75rem 0 .6rem;
      font-size: .8rem;
    }
    .detail-grid dt { color: var(--muted); }
    .detail-grid dd {
      font-family: monospace;
      word-break: break-all;
      white-space: pre-wrap;
    }

    .entries-heading {
      font-size: .75rem;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--muted);
      margin: .5rem 0 .4rem;
    }
    .entry-row {
      font-family: monospace;
      font-size: .75rem;
      padding: .3rem .5rem;
      border-radius: 3px;
      background: var(--bg);
      margin-bottom: .3rem;
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      color: var(--muted);
      word-break: break-all;
    }
    .entry-row span { color: var(--text); }

    .empty-state {
      text-align: center;
      color: var(--muted);
      padding: 3rem 1rem;
      font-size: .95rem;
    }
  </style>
</head>
<body>

<header>
  <h1>Workspace Security Monitor</h1>
  <div class="header-meta">
    <span id="last-updated">—</span>
    <span id="countdown">—</span>
  </div>
</header>

<main>
  <!-- Stats bar -->
  <div class="stat-bar">
    <div class="stat-card stat-total">
      <span class="label">Total Alerts</span>
      <span class="value" id="stat-total">—</span>
    </div>
    <div class="stat-card stat-high">
      <span class="label">High</span>
      <span class="value" id="stat-high">—</span>
    </div>
    <div class="stat-card stat-medium">
      <span class="label">Medium</span>
      <span class="value" id="stat-medium">—</span>
    </div>
    <div class="stat-card stat-low">
      <span class="label">Low</span>
      <span class="value" id="stat-low">—</span>
    </div>
  </div>

  <!-- Filter bar -->
  <div class="filter-bar">
    <label>Severity
      <select id="f-severity">
        <option value="">All severities</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
    </label>
    <label>Source
      <select id="f-source">
        <option value="">All sources</option>
        <option value="workspace">Workspace</option>
        <option value="auth">Auth</option>
        <option value="web">Web</option>
      </select>
    </label>
    <label>Search description
      <input type="text" id="f-search" placeholder="e.g. brute force, 192.168…">
    </label>
    <div class="filter-actions">
      <button class="btn-secondary" id="btn-clear">Clear</button>
      <button class="btn-primary"   id="btn-refresh">Refresh Now</button>
    </div>
  </div>

  <!-- Alert list -->
  <div id="alert-list"><div class="empty-state">Loading…</div></div>
</main>

<script>
  'use strict';

  const AUTO_REFRESH_MS = 6 * 60 * 60 * 1000;
  let   nextRefreshAt   = Date.now() + AUTO_REFRESH_MS;
  let   allAlerts       = [];

  // ── Helpers ──────────────────────────────────────────────────────────────

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function fmtTs(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
  }

  function fmtCountdown(ms) {
    if (ms <= 0) return '0s';
    const h = Math.floor(ms / 3_600_000);
    const m = Math.floor((ms % 3_600_000) / 60_000);
    const s = Math.floor((ms % 60_000) / 1000);
    return h ? `${h}h ${m}m` : m ? `${m}m ${s}s` : `${s}s`;
  }

  function truncate(str, max) {
    if (!str) return '';
    return str.length > max ? str.slice(0, max) + '…' : str;
  }

  const STATUS_LABELS = {
    new:                'New',
    in_progress:        'In Progress',
    resolved:           'Resolved',
    resolved_no_action: 'Resolved — No Action',
  };

  // ── Stats ─────────────────────────────────────────────────────────────────

  async function loadStats() {
    try {
      const r = await fetch('/api/stats');
      const s = await r.json();
      document.getElementById('stat-total').textContent  = s.total ?? 0;
      document.getElementById('stat-high').textContent   = s.by_severity?.high   ?? 0;
      document.getElementById('stat-medium').textContent = s.by_severity?.medium ?? 0;
      document.getElementById('stat-low').textContent    = s.by_severity?.low    ?? 0;
    } catch (e) {
      console.error('Stats fetch failed', e);
    }
  }

  // ── Status management ─────────────────────────────────────────────────────

  async function postStatus(alertId, status) {
    await fetch(`/api/status/${encodeURIComponent(alertId)}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ status }),
    });
  }

  function buildStatusSelect(alertId, currentStatus) {
    const sel = document.createElement('select');
    sel.className = `status-select ${currentStatus}`;

    for (const [val, label] of Object.entries(STATUS_LABELS)) {
      const opt = document.createElement('option');
      opt.value = val;
      opt.textContent = label;
      if (val === currentStatus) opt.selected = true;
      sel.appendChild(opt);
    }

    sel.addEventListener('click', e => e.stopPropagation());  // don't toggle card
    sel.addEventListener('change', async () => {
      const newStatus = sel.value;
      sel.className = `status-select ${newStatus}`;
      await postStatus(alertId, newStatus);

      if (newStatus === 'resolved' || newStatus === 'resolved_no_action') {
        const card = sel.closest('.alert-card');
        card.classList.add('fading');
        setTimeout(() => card.remove(), 620);
      }
    });

    return sel;
  }

  // ── Alert rendering ───────────────────────────────────────────────────────

  function buildCard(a) {
    const sev     = (a.severity ?? 'low').toLowerCase();
    const status  = a.status ?? 'new';
    const entries = a.triggering_entries ?? [];

    const entryHtml = entries.map(e =>
      `<div class="entry-row">
        <span>${esc(fmtTs(e.timestamp))}</span>
        <span>${esc(e.source_ip ?? '?')}</span>
        <span>${esc(e.log_type ?? '?')}</span>
        <span>${esc(e.raw_message ?? '')}</span>
       </div>`
    ).join('');

    const card = document.createElement('div');
    card.className = `alert-card ${esc(sev)}`;
    card.dataset.alertId = a.alert_id ?? '';

    // Build header manually so we can inject the status <select> node
    const header = document.createElement('div');
    header.className = 'card-header';
    header.innerHTML = `
      <span class="badge badge-${esc(sev)}">${esc(sev)}</span>
      <span class="card-desc" title="${esc(a.description)}">${esc(truncate(a.description, 120))}</span>
      <div class="card-meta">
        <span>${esc(a.source_ip ?? '—')}</span>
        <span>${esc(fmtTs(a.timestamp))}</span>
        <span>${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}</span>
      </div>`;

    header.appendChild(buildStatusSelect(a.alert_id, status));
    header.insertAdjacentHTML('beforeend', '<span class="expand-icon">▼</span>');

    const detail = document.createElement('div');
    detail.className = 'card-detail';
    detail.innerHTML = `
      <dl class="detail-grid">
        <dt>Alert ID</dt>   <dd>${esc(a.alert_id)}</dd>
        <dt>Status</dt>     <dd>${esc(STATUS_LABELS[status] ?? status)}</dd>
        <dt>Severity</dt>   <dd>${esc(a.severity)}</dd>
        <dt>Source IP</dt>  <dd>${esc(a.source_ip)}</dd>
        <dt>Timestamp</dt>  <dd>${esc(fmtTs(a.timestamp))}</dd>
        <dt>Fetched at</dt> <dd>${esc(fmtTs(a.fetched_at))}</dd>
        <dt>Description</dt><dd>${esc(a.description)}</dd>
      </dl>
      ${entries.length ? `
        <div class="entries-heading">Triggering entries (${entries.length})</div>
        ${entryHtml}` : ''}`;

    card.appendChild(header);
    card.appendChild(detail);

    header.addEventListener('click', () => card.classList.toggle('open'));
    return card;
  }

  function applyFilters() {
    const sev    = document.getElementById('f-severity').value.toLowerCase();
    const src    = document.getElementById('f-source').value.toLowerCase();
    const search = document.getElementById('f-search').value.toLowerCase();

    const filtered = allAlerts.filter(a => {
      if (sev && (a.severity ?? '').toLowerCase() !== sev) return false;
      if (src) {
        const logSrc = (a.log_source ?? '').toLowerCase();
        const entSrc = (a.triggering_entries ?? [])
          .some(e => (e.log_type ?? '').toLowerCase() === src);
        if (logSrc !== src && !entSrc) return false;
      }
      if (search && !(a.description ?? '').toLowerCase().includes(search)) return false;
      return true;
    });

    const list = document.getElementById('alert-list');
    list.innerHTML = '';
    if (!filtered.length) {
      list.innerHTML = '<div class="empty-state">No alerts match the current filters.</div>';
      return;
    }
    const frag = document.createDocumentFragment();
    filtered.forEach(a => frag.appendChild(buildCard(a)));
    list.appendChild(frag);
  }

  // ── Data fetch ────────────────────────────────────────────────────────────

  async function refresh() {
    document.getElementById('last-updated').textContent =
      new Date().toLocaleTimeString();
    nextRefreshAt = Date.now() + AUTO_REFRESH_MS;

    try {
      const r = await fetch('/api/alerts?limit=500');
      allAlerts = await r.json();
    } catch (e) {
      console.error('Alert fetch failed', e);
    }

    await loadStats();
    applyFilters();
  }

  // ── Countdown ticker ──────────────────────────────────────────────────────

  setInterval(() => {
    const remaining = nextRefreshAt - Date.now();
    document.getElementById('countdown').textContent = fmtCountdown(remaining);
    if (remaining <= 0) refresh();
  }, 1000);

  // ── Event listeners ───────────────────────────────────────────────────────

  document.getElementById('btn-refresh').addEventListener('click', refresh);

  document.getElementById('btn-clear').addEventListener('click', () => {
    document.getElementById('f-severity').value = '';
    document.getElementById('f-source').value   = '';
    document.getElementById('f-search').value   = '';
    applyFilters();
  });

  ['f-severity','f-source'].forEach(id =>
    document.getElementById(id).addEventListener('change', applyFilters));

  document.getElementById('f-search').addEventListener('input', applyFilters);

  // ── Boot ──────────────────────────────────────────────────────────────────

  refresh();
</script>
</body>
</html>"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _alert_id(alert: dict) -> str:
    """Stable hash of timestamp + source_ip + description."""
    key = (
        str(alert.get("timestamp", ""))
        + str(alert.get("source_ip", ""))
        + str(alert.get("description", ""))
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _read_status() -> dict:
    if not _STATUS_FILE.exists():
        return {}
    try:
        return json.loads(_STATUS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_status(data: dict) -> None:
    _STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATUS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _read_alerts() -> list[dict]:
    """Parse alerts.json (JSONL), attach IDs and statuses, return newest first."""
    if not _ALERT_LOG.exists():
        return []
    alerts = []
    with _ALERT_LOG.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    status_map = _read_status()
    for a in alerts:
        aid = _alert_id(a)
        a["alert_id"] = aid
        a["status"]   = status_map.get(aid, "new")

    alerts.sort(key=lambda a: a.get("timestamp") or a.get("fetched_at") or "", reverse=True)
    return alerts


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(_DASHBOARD_HTML)


@app.route("/api/alerts")
def api_alerts():
    severity = request.args.get("severity", "").lower()
    source   = request.args.get("source", "").lower()
    try:
        limit = min(int(request.args.get("limit", 500)), 500)
    except ValueError:
        limit = 500

    alerts = _read_alerts()

    if severity:
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity]
    if source:
        def _matches_source(a):
            if a.get("log_source", "").lower() == source:
                return True
            entries = a.get("triggering_entries") or []
            return any(e.get("log_type", "").lower() == source for e in entries)
        alerts = [a for a in alerts if _matches_source(a)]

    return jsonify(alerts[:limit])


@app.route("/api/status", methods=["GET"])
def api_status_get():
    return jsonify(_read_status())


@app.route("/api/status/<alert_id>", methods=["POST"])
def api_status_post(alert_id: str):
    body = request.get_json(silent=True) or {}
    status = body.get("status", "")
    if status not in _VALID_STATUSES:
        return jsonify({"error": f"Invalid status. Must be one of: {sorted(_VALID_STATUSES)}"}), 400

    data = _read_status()
    data[alert_id] = status
    _write_status(data)
    return jsonify({"alert_id": alert_id, "status": status})


@app.route("/api/stats")
def api_stats():
    alerts = _read_alerts()

    by_severity: dict[str, int] = {}
    by_source:   dict[str, int] = {}

    for a in alerts:
        sev = a.get("severity", "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

        src = a.get("log_source", "").lower()
        if not src:
            entries = a.get("triggering_entries") or []
            src = entries[0].get("log_type", "unknown").lower() if entries else "unknown"
        by_source[src] = by_source.get(src, 0) + 1

    timestamps = [a["timestamp"] for a in alerts if "timestamp" in a]

    return jsonify({
        "total":        len(alerts),
        "by_severity":  by_severity,
        "by_source":    by_source,
        "newest_alert": timestamps[0]  if timestamps else None,
        "oldest_alert": timestamps[-1] if timestamps else None,
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
