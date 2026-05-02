from collections import defaultdict, deque
from datetime import timedelta
from typing import Any, Deque, Dict, Iterable, List, Tuple

from src.utils import get_nested_value, parse_event_time, utc_now_iso


class Correlator:
    """Detecta patrones temporales que requieren memoria entre eventos."""

    def __init__(self, window_minutes: int = 10, failed_login_threshold: int = 3):
        self.window = timedelta(minutes=window_minutes)
        self.failed_login_threshold = failed_login_threshold
        self.failed_logins: Dict[Tuple[str, str], Deque[Dict[str, Any]]] = defaultdict(deque)
        self.high_risk_by_source: Dict[str, Deque[Dict[str, Any]]] = defaultdict(deque)
        self._seen_alerts = set()

    def process_event(
        self,
        event: Dict[str, Any],
        rule_results: Iterable[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        event_time = parse_event_time(event)
        source_ip = str(get_nested_value(event, "source.ip", event.get("source_ip", "unknown")))
        username = str(get_nested_value(event, "user.name", event.get("username", "unknown")))
        event_type = str(event.get("event_type", "")).lower()
        outcome = str(get_nested_value(event, "event.outcome", event.get("outcome", ""))).lower()

        alerts: List[Dict[str, Any]] = []
        key = (source_ip, username)

        self._expire(self.failed_logins[key], event_time)
        self._expire(self.high_risk_by_source[source_ip], event_time)

        if event_type == "authentication" and outcome == "failure":
            self.failed_logins[key].append(event)
            if len(self.failed_logins[key]) >= self.failed_login_threshold:
                alerts.append(
                    self._build_alert(
                        "corr-bruteforce",
                        "Possible brute force activity",
                        "Multiples fallos de autenticacion en una ventana corta.",
                        "high",
                        event,
                        {
                            "source_ip": source_ip,
                            "username": username,
                            "failures": len(self.failed_logins[key]),
                            "window_minutes": int(self.window.total_seconds() / 60),
                            "related_events": [item.get("id") for item in self.failed_logins[key]],
                        },
                    )
                )

        if event_type == "authentication" and outcome == "success" and self.failed_logins[key]:
            alerts.append(
                self._build_alert(
                    "corr-login-after-failures",
                    "Successful login after failures",
                    "Un acceso exitoso ocurrio despues de varios fallos recientes.",
                    "critical",
                    event,
                    {
                        "source_ip": source_ip,
                        "username": username,
                        "previous_failures": len(self.failed_logins[key]),
                        "related_events": [item.get("id") for item in self.failed_logins[key]],
                    },
                )
            )

        high_rule_hits = [
            result
            for result in rule_results
            if result.get("matched") and result.get("severity") in {"high", "critical"}
        ]
        for result in high_rule_hits:
            self.high_risk_by_source[source_ip].append(
                {
                    "id": event.get("id"),
                    "timestamp": event.get("timestamp"),
                    "rule_id": result.get("rule_id"),
                    "name": result.get("name"),
                }
            )

        process_name = str(get_nested_value(event, "process.name", "")).lower()
        suspicious_processes = {"powershell.exe", "rundll32.exe", "certutil.exe", "wmic.exe"}
        if process_name in suspicious_processes and self.high_risk_by_source[source_ip]:
            alerts.append(
                self._build_alert(
                    "corr-high-risk-process-chain",
                    "High-risk event followed by suspicious process",
                    "Se observo una cadena de actividad riesgosa desde la misma fuente.",
                    "critical",
                    event,
                    {
                        "source_ip": source_ip,
                        "process": process_name,
                        "previous_high_risk_events": list(self.high_risk_by_source[source_ip]),
                    },
                )
            )

        return [alert for alert in alerts if self._mark_once(alert)]

    def _expire(self, queue: Deque[Dict[str, Any]], current_time) -> None:
        while queue and current_time - parse_event_time(queue[0]) > self.window:
            queue.popleft()

    def _build_alert(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: str,
        event: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        event_id = event.get("id", "<no-id>")
        return {
            "alert_id": f"{event_id}:{rule_id}",
            "event_id": event_id,
            "rule_id": rule_id,
            "name": name,
            "description": description,
            "severity": severity,
            "metadata": metadata,
            "created_at": utc_now_iso(),
            "source": "correlation",
        }

    def _mark_once(self, alert: Dict[str, Any]) -> bool:
        alert_id = alert.get("alert_id")
        if alert_id in self._seen_alerts:
            return False
        self._seen_alerts.add(alert_id)
        return True
