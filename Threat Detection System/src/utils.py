import json
import logging
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )


def load_events_from_jsonl(path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logging.getLogger(__name__).warning(
                    "Linea %d no es JSON valido y sera ignorada: %s", line_no, exc
                )
    return events


def get_nested_value(data: Dict[str, Any], dotted_path: str, default: Any = None) -> Any:
    current: Any = data
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_event_time(event: Dict[str, Any]) -> datetime:
    value = event.get("timestamp") or event.get("@timestamp") or event.get("time")
    if not value:
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def pretty_print_results(event: Dict[str, Any], results: Iterable[Dict[str, Any]]) -> None:
    logger = logging.getLogger(__name__)
    results_list = list(results)
    event_id = event.get("id", "<no-id>")
    matched = [result for result in results_list if result.get("matched")]
    logger.info("Evento %s | coincidencias: %d/%d", event_id, len(matched), len(results_list))
    for result in results_list:
        status = "MATCH" if result.get("matched") else "no match"
        rule_id = result.get("rule_id", result.get("id", "<no-rule-id>"))
        logger.debug(
            "  - %s | %s | %s | %s",
            rule_id,
            result.get("severity", "low"),
            result.get("name", ""),
            status,
        )


def write_json_report(path: str, payload: Dict[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_html_report(path: str, payload: Dict[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    alerts = payload.get("alerts", [])
    summary = payload.get("summary", {})
    rows = []
    for alert in alerts:
        severity = str(alert.get("severity", "low")).lower()
        rows.append(
            "<tr>"
            f"<td>{escape(str(alert.get('event_id', '')))}</td>"
            f"<td><span class='sev {escape(severity)}'>{escape(severity.upper())}</span></td>"
            f"<td>{escape(str(alert.get('source', 'rule')))}</td>"
            f"<td>{escape(str(alert.get('rule_id', '')))}</td>"
            f"<td>{escape(str(alert.get('name', '')))}</td>"
            f"<td>{escape(str(alert.get('description', '')))}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Threat Detection Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #667085;
      --line: #e5e7eb;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, "Segoe UI", Arial, sans-serif;
      line-height: 1.5;
    }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 32px 20px; }}
    header {{ display: flex; justify-content: space-between; gap: 20px; align-items: end; margin-bottom: 24px; }}
    h1 {{ margin: 0; font-size: 28px; letter-spacing: 0; }}
    .muted {{ color: var(--muted); margin: 4px 0 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 18px; }}
    .metric, table {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }}
    .metric {{ padding: 16px; }}
    .metric span {{ display: block; color: var(--muted); font-size: 13px; }}
    .metric strong {{ display: block; margin-top: 6px; font-size: 24px; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
    tr:last-child td {{ border-bottom: 0; }}
    .sev {{ display: inline-block; min-width: 72px; border-radius: 999px; padding: 3px 8px; text-align: center; font-size: 12px; font-weight: 700; }}
    .critical {{ background: #fee2e2; color: #991b1b; }}
    .high {{ background: #ffedd5; color: #9a3412; }}
    .medium {{ background: #fef3c7; color: #92400e; }}
    .low {{ background: #dbeafe; color: #1e40af; }}
    @media (max-width: 760px) {{
      header {{ display: block; }}
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>Threat Detection Report</h1>
      <p class="muted">Generado: {escape(str(payload.get("generated_at", "")))}</p>
    </div>
    <p class="muted">{escape(str(summary.get("rules_loaded", 0)))} reglas cargadas</p>
  </header>
  <section class="grid">
    <div class="metric"><span>Eventos</span><strong>{summary.get("events_processed", 0)}</strong></div>
    <div class="metric"><span>Alertas</span><strong>{summary.get("alerts_total", 0)}</strong></div>
    <div class="metric"><span>Criticas/Altas</span><strong>{summary.get("high_priority_alerts", 0)}</strong></div>
    <div class="metric"><span>Reglas</span><strong>{summary.get("rules_loaded", 0)}</strong></div>
  </section>
  <table>
    <thead><tr><th>Evento</th><th>Severidad</th><th>Fuente</th><th>Regla</th><th>Nombre</th><th>Descripcion</th></tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="6">No se detectaron alertas.</td></tr>'}</tbody>
  </table>
</main>
</body>
</html>"""
    output.write_text(html, encoding="utf-8")


def default_report_path(extension: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return str(Path("reports") / f"threat-report-{stamp}.{extension}")


def severity_rank(value: Optional[str]) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(value or "low").lower(), 1)
