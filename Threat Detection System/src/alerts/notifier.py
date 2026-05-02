import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable

LOGGER = logging.getLogger(__name__)


class ConsoleNotifier:
    def send(self, alerts: Iterable[Dict[str, Any]]) -> None:
        for alert in alerts:
            LOGGER.warning(
                "ALERTA %-8s | evento=%s | regla=%s | %s",
                str(alert.get("severity", "low")).upper(),
                alert.get("event_id"),
                alert.get("rule_id"),
                alert.get("name"),
            )


class FileNotifier:
    def __init__(self, path: str, reset: bool = True):
        self.path = Path(path)
        if reset and self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def send(self, alerts: Iterable[Dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(alert, ensure_ascii=False) + "\n")
