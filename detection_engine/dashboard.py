"""Self-contained interactive SOC HTML Dashboard generator (zero CDN / zero external deps)."""

from __future__ import annotations

import html
from pathlib import Path

from detection_engine.models import DetectionReport


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _sev_class(severity: str) -> str:
    sev = severity.lower()
    if sev in {"critical", "high", "medium", "low"}:
        return f"sev-{sev}"
    return "sev-info"


def render_html_dashboard(report: DetectionReport) -> str:
    """Render a standalone, XSS-safe dark-mode SOC HTML dashboard from a DetectionReport."""
    sev = report.severity_counts()
    total_alerts = len(report.alerts)
    total_incidents = len(report.incidents)
    ti_hit_count = sum(1 for a in report.alerts if any(i.is_malicious for i in a.iocs))
    mitre_list = report.mitre_summary()

    # Severity bar widths
    denom = max(total_alerts, 1)
    bar_segments = []
    for level, color in (
        ("critical", "#ef4444"),
        ("high", "#f97316"),
        ("medium", "#eab308"),
        ("low", "#38bdf8"),
    ):
        count = sev.get(level, 0)
        pct = round((count / denom) * 100, 1)
        if count > 0:
            bar_segments.append(
                f'<div class="bar-seg" style="width:{pct}%;background:{color};" '
                f'title="{level.upper()}: {count} ({pct}%)"></div>'
            )
    sev_bar_html = "".join(bar_segments) or '<div class="bar-seg" style="width:100%;background:#22c55e;"></div>'

    # Correlated Incidents HTML
    incident_cards: list[str] = []
    for inc in report.incidents:
        stages_html = " <span class='arrow'>&rarr;</span> ".join(
            f'<span class="stage-pill">{_esc(st)}</span>' for st in inc.kill_chain_stages
        ) or '<span class="stage-pill">Single Stage</span>'
        ioc_badges = "".join(
            f'<span class="ioc-badge">{_esc(ioc)}</span>' for ioc in inc.malicious_iocs
        ) or '<span class="muted">None</span>'
        pb_badges = "".join(
            f'<span class="pb-badge">{_esc(pb)}</span>' for pb in inc.playbooks
        ) or '<span class="muted">N/A</span>'
        incident_cards.append(
            f"""
            <article class="incident-card {_sev_class(inc.severity)}">
              <div class="inc-head">
                <div>
                  <span class="badge {_sev_class(inc.severity)}">{_esc(inc.severity.upper())}</span>
                  <strong class="inc-id">{_esc(inc.incident_id)}</strong>
                  <span class="entity-chip">{_esc(inc.entity)}</span>
                </div>
                <div class="risk-box">
                  <span class="risk-label">Risk Score</span>
                  <strong class="risk-val">{inc.risk_score}/100</strong>
                </div>
              </div>
              <p class="inc-summary">{_esc(inc.summary)}</p>
              <div class="kill-chain"><strong>Kill Chain:</strong> {stages_html}</div>
              <div class="inc-meta">
                <div><strong>Window:</strong> <code>{_esc(inc.first_seen)}</code> &rarr; <code>{_esc(inc.last_seen)}</code></div>
                <div><strong>Alerts:</strong> {len(inc.alert_ids)} | <strong>Playbooks:</strong> {pb_badges}</div>
                <div><strong>Malicious IOCs:</strong> {ioc_badges}</div>
              </div>
            </article>
            """
        )
    incidents_html = (
        "".join(incident_cards)
        if incident_cards
        else '<p class="muted">No correlated incidents detected.</p>'
    )

    # Alert Rows HTML
    alert_cards: list[str] = []
    for alert in report.alerts:
        mitre_badges = "".join(
            f'<span class="mitre-pill">{_esc(t)}</span>' for t in alert.mitre_techniques
        ) or '<span class="muted">N/A</span>'
        ioc_html = "".join(
            f'<span class="{"ioc-badge" if ioc.is_malicious else "ioc-benign"}">'
            f'{_esc(ioc.value)} ({_esc(ioc.classification)})</span>'
            for ioc in alert.iocs
        ) or '<span class="muted">None extracted</span>'
        notes_html = "".join(f"<li>{_esc(note)}</li>" for note in alert.enrichment_notes)
        evidence_text = "\n".join(alert.evidence[:5])
        search_blob = _esc(
            f"{alert.alert_id} {alert.rule_title} {alert.entity} {alert.severity} "
            f"{' '.join(alert.mitre_techniques)} {' '.join(alert.mitre_tactics)} {alert.playbook_id}"
        ).lower()

        alert_cards.append(
            f"""
            <article class="alert-card" data-severity="{_esc(alert.severity.lower())}" data-search="{search_blob}">
              <div class="alert-top">
                <div class="alert-title-row">
                  <span class="badge {_sev_class(alert.severity)}">{_esc(alert.severity.upper())}</span>
                  <h3>{_esc(alert.rule_title)}</h3>
                </div>
                <div class="alert-ids">
                  <code>{_esc(alert.alert_id)}</code>
                  <span class="pb-badge">{_esc(alert.playbook_id or "N/A")}</span>
                </div>
              </div>
              <div class="alert-grid">
                <div><strong>Entity:</strong> <code>{_esc(alert.entity)}</code></div>
                <div><strong>Events:</strong> {alert.event_count}</div>
                <div><strong>MITRE:</strong> {mitre_badges}</div>
                <div><strong>Window:</strong> <code>{_esc(alert.first_seen)}</code></div>
              </div>
              <p class="alert-desc">{_esc(alert.description)}</p>
              <div class="alert-iocs"><strong>IOCs:</strong> {ioc_html}</div>
              {f'<ul class="ti-notes">{notes_html}</ul>' if notes_html else ''}
              <details class="evidence-box">
                <summary>Inspect Raw Telemetry Evidence ({len(alert.evidence)} sample(s))</summary>
                <pre>{_esc(evidence_text)}</pre>
              </details>
            </article>
            """
        )

    alerts_html = (
        "".join(alert_cards)
        if alert_cards
        else '<p class="ok-banner">No security alerts triggered. Telemetry appears benign.</p>'
    )
    mitre_summary_pills = "".join(
        f'<span class="mitre-pill">{_esc(tech)}</span>' for tech in mitre_list
    ) or '<span class="muted">None</span>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Detection-as-Code Lab — SOC Operations Dashboard</title>
  <style>
    :root {{
      --bg: #0b1120;
      --surface: #111827;
      --surface-2: #1e293b;
      --border: #2d3b52;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #38bdf8;
      --ok: #22c55e;
      --accent: #3b82f6;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .wrap {{ max-width: 1220px; margin: 0 auto; padding: 24px 20px 48px; }}
    header {{
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
      gap: 16px; border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 24px;
    }}
    header h1 {{ margin: 0; font-size: 1.55rem; letter-spacing: 0.01em; }}
    .subtitle {{ color: var(--muted); font-size: 0.9rem; margin-top: 4px; }}
    .meta-pill {{
      background: var(--surface-2); border: 1px solid var(--border);
      padding: 6px 12px; border-radius: 999px; font-size: 0.8rem; color: var(--muted);
    }}
    .kpi-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
      gap: 14px; margin-bottom: 22px;
    }}
    .kpi {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; padding: 16px;
    }}
    .kpi-label {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; }}
    .kpi-value {{ font-size: 1.9rem; font-weight: 700; margin-top: 6px; }}
    .kpi-crit {{ color: var(--crit); }}
    .kpi-high {{ color: var(--high); }}
    .kpi-accent {{ color: var(--low); }}
    .sev-bar {{
      display: flex; height: 10px; border-radius: 999px; overflow: hidden;
      background: var(--surface-2); margin: 12px 0 26px;
    }}
    .bar-seg {{ height: 100%; }}
    section {{ margin-bottom: 30px; }}
    h2 {{
      font-size: 1.15rem; margin: 0 0 14px; display: flex; align-items: center; gap: 10px;
      border-left: 4px solid var(--accent); padding-left: 10px;
    }}
    .badge {{
      display: inline-block; padding: 2px 9px; border-radius: 6px;
      font-size: 0.72rem; font-weight: 700; letter-spacing: 0.05em;
    }}
    .sev-critical {{ background: rgba(239,68,68,0.18); color: #fca5a5; border: 1px solid rgba(239,68,68,0.45); }}
    .sev-high {{ background: rgba(249,115,22,0.18); color: #fdba74; border: 1px solid rgba(249,115,22,0.45); }}
    .sev-medium {{ background: rgba(234,179,8,0.18); color: #fde047; border: 1px solid rgba(234,179,8,0.45); }}
    .sev-low, .sev-info {{ background: rgba(56,189,248,0.16); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.4); }}
    .incident-card {{
      background: var(--surface); border: 1px solid var(--border); border-left-width: 4px;
      border-radius: 10px; padding: 16px 18px; margin-bottom: 14px;
    }}
    .incident-card.sev-critical {{ border-left-color: var(--crit); }}
    .incident-card.sev-high {{ border-left-color: var(--high); }}
    .incident-card.sev-medium {{ border-left-color: var(--med); }}
    .inc-head {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }}
    .inc-id {{ margin: 0 8px; font-family: ui-monospace, monospace; }}
    .entity-chip {{
      background: var(--surface-2); padding: 2px 8px; border-radius: 6px;
      font-family: ui-monospace, monospace; font-size: 0.85rem;
    }}
    .risk-box {{ text-align: right; }}
    .risk-label {{ display: block; font-size: 0.7rem; color: var(--muted); text-transform: uppercase; }}
    .risk-val {{ font-size: 1.25rem; color: #f8fafc; }}
    .inc-summary {{ margin: 10px 0; color: #cbd5e1; font-size: 0.92rem; }}
    .kill-chain {{ display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 10px 0; font-size: 0.85rem; }}
    .stage-pill {{
      background: rgba(59,130,246,0.18); border: 1px solid rgba(59,130,246,0.45);
      color: #93c5fd; padding: 2px 8px; border-radius: 999px; font-size: 0.78rem;
    }}
    .arrow {{ color: var(--muted); }}
    .inc-meta {{ display: flex; flex-wrap: wrap; gap: 14px; font-size: 0.83rem; color: var(--muted); margin-top: 8px; }}
    .controls {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 16px; }}
    .filter-btn {{
      background: var(--surface); color: var(--text); border: 1px solid var(--border);
      padding: 6px 12px; border-radius: 8px; cursor: pointer; font-size: 0.82rem; font-weight: 600;
    }}
    .filter-btn.active {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
    .search-input {{
      flex: 1; min-width: 220px; background: var(--surface); color: var(--text);
      border: 1px solid var(--border); border-radius: 8px; padding: 7px 12px; font-size: 0.88rem;
    }}
    .alert-card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; padding: 16px; margin-bottom: 12px;
    }}
    .alert-top {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }}
    .alert-title-row {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .alert-title-row h3 {{ margin: 0; font-size: 1rem; }}
    .alert-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 8px; margin: 10px 0; font-size: 0.85rem; color: #cbd5e1;
    }}
    .alert-desc {{ margin: 6px 0 10px; color: var(--muted); font-size: 0.88rem; }}
    .alert-iocs {{ display: flex; flex-wrap: wrap; align-items: center; gap: 6px; font-size: 0.82rem; margin-bottom: 8px; }}
    .mitre-pill {{
      display: inline-block; background: rgba(168,85,247,0.18); border: 1px solid rgba(168,85,247,0.45);
      color: #d8b4fe; padding: 1px 7px; border-radius: 6px; font-family: ui-monospace, monospace; font-size: 0.76rem;
      margin-right: 4px;
    }}
    .pb-badge {{
      display: inline-block; background: rgba(34,197,94,0.16); border: 1px solid rgba(34,197,94,0.4);
      color: #86efac; padding: 1px 7px; border-radius: 6px; font-family: ui-monospace, monospace; font-size: 0.76rem;
    }}
    .ioc-badge {{
      display: inline-block; background: rgba(239,68,68,0.18); border: 1px solid rgba(239,68,68,0.45);
      color: #fca5a5; padding: 1px 7px; border-radius: 6px; font-family: ui-monospace, monospace; font-size: 0.76rem;
    }}
    .ioc-benign {{
      display: inline-block; background: var(--surface-2); border: 1px solid var(--border);
      color: var(--muted); padding: 1px 7px; border-radius: 6px; font-family: ui-monospace, monospace; font-size: 0.76rem;
    }}
    .ti-notes {{ margin: 8px 0 10px 18px; padding: 0; font-size: 0.83rem; color: #fcd34d; }}
    .evidence-box summary {{ cursor: pointer; font-size: 0.82rem; color: #93c5fd; }}
    .evidence-box pre {{
      background: #020617; border: 1px solid var(--border); border-radius: 8px;
      padding: 10px; overflow-x: auto; font-size: 0.78rem; color: #e2e8f0; margin-top: 8px;
    }}
    .mitre-box {{
      background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
      padding: 14px; display: flex; flex-wrap: wrap; gap: 6px;
    }}
    .muted {{ color: var(--muted); }}
    .ok-banner {{
      background: rgba(34,197,94,0.14); border: 1px solid rgba(34,197,94,0.4);
      color: #86efac; padding: 14px; border-radius: 10px;
    }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.84em; }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <h1>Detection-as-Code Lab &mdash; SOC Operations Dashboard</h1>
        <div class="subtitle">Sigma Rules &bull; Cross-Source Kill-Chain Correlation &bull; Threat Intel Enrichment &bull; MITRE ATT&amp;CK</div>
      </div>
      <div class="meta-pill">Generated UTC: {_esc(report.generated_at)}</div>
    </header>

    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Sigma Rules</div><div class="kpi-value kpi-accent">{report.rules_loaded}</div></div>
      <div class="kpi"><div class="kpi-label">Events Processed</div><div class="kpi-value">{report.events_processed}</div></div>
      <div class="kpi"><div class="kpi-label">Correlated Incidents</div><div class="kpi-value kpi-high">{total_incidents}</div></div>
      <div class="kpi"><div class="kpi-label">Total Alerts</div><div class="kpi-value">{total_alerts}</div></div>
      <div class="kpi"><div class="kpi-label">Critical / High</div><div class="kpi-value kpi-crit">{sev['critical']} / {sev['high']}</div></div>
      <div class="kpi"><div class="kpi-label">TI-Confirmed Alerts</div><div class="kpi-value kpi-high">{ti_hit_count}</div></div>
    </div>

    <div class="sev-bar" aria-label="Alert severity breakdown">{sev_bar_html}</div>

    <section>
      <h2>MITRE ATT&amp;CK Techniques Observed ({len(mitre_list)})</h2>
      <div class="mitre-box">{mitre_summary_pills}</div>
    </section>

    <section>
      <h2>Correlated Kill-Chain Incidents ({total_incidents})</h2>
      {incidents_html}
    </section>

    <section>
      <h2>Actionable SOC Alerts ({total_alerts})</h2>
      <div class="controls">
        <button class="filter-btn active" data-filter="all">All ({total_alerts})</button>
        <button class="filter-btn" data-filter="critical">Critical ({sev['critical']})</button>
        <button class="filter-btn" data-filter="high">High ({sev['high']})</button>
        <button class="filter-btn" data-filter="medium">Medium ({sev['medium']})</button>
        <button class="filter-btn" data-filter="low">Low ({sev['low']})</button>
        <input id="alert-search" class="search-input" type="search" placeholder="Filter by entity, rule title, MITRE technique, or playbook...">
      </div>
      <div id="alerts-list">{alerts_html}</div>
    </section>
  </div>

  <script>
    (function () {{
      let activeSeverity = "all";
      const buttons = document.querySelectorAll(".filter-btn");
      const searchInput = document.getElementById("alert-search");
      const cards = document.querySelectorAll(".alert-card");

      function applyFilters() {{
        const q = (searchInput.value || "").trim().toLowerCase();
        cards.forEach((card) => {{
          const sev = card.getAttribute("data-severity") || "";
          const hay = card.getAttribute("data-search") || "";
          const matchesSev = activeSeverity === "all" || sev === activeSeverity;
          const matchesText = !q || hay.includes(q);
          card.style.display = (matchesSev && matchesText) ? "" : "none";
        }});
      }}

      buttons.forEach((btn) => {{
        btn.addEventListener("click", () => {{
          buttons.forEach((b) => b.classList.remove("active"));
          btn.classList.add("active");
          activeSeverity = btn.getAttribute("data-filter") || "all";
          applyFilters();
        }});
      }});
      searchInput.addEventListener("input", applyFilters);
    }})();
  </script>
</body>
</html>
"""


def write_html_dashboard(report: DetectionReport, output_path: str | Path) -> Path:
    """Write standalone HTML SOC dashboard to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_dashboard(report), encoding="utf-8")
    return path
