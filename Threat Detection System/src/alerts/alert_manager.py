from typing import Any, Dict, Iterable, List

from src.utils import severity_rank, utc_now_iso


class AlertManager:
    """Convierte coincidencias de reglas en alertas priorizadas."""

    def __init__(self, min_severity: str = "low"):
        self.min_severity = min_severity

    def build_alerts(
        self,
        event: Dict[str, Any],
        results: Iterable[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        event_id = event.get("id", "<no-id>")
        alerts: List[Dict[str, Any]] = []
        for result in results:
            severity = result.get("severity", "low")
            if not result.get("matched") or severity_rank(severity) < severity_rank(self.min_severity):
                continue
            alerts.append(
                {
                    "alert_id": f"{event_id}:{result.get('rule_id')}",
                    "event_id": event_id,
                    "rule_id": result.get("rule_id"),
                    "name": result.get("name"),
                    "description": result.get("description", ""),
                    "severity": severity,
                    "metadata": result.get("metadata", {}),
                    "created_at": utc_now_iso(),
                }
            )
        return sorted(alerts, key=lambda item: severity_rank(item.get("severity")), reverse=True)
