import logging
from typing import Any, Dict, List

from src.rules.base_rule import BaseRule

from .detection_strategy import DetectionStrategy, SequentialStrategy

LOGGER = logging.getLogger(__name__)


class Detector:
    """Orquesta la evaluacion de reglas contra eventos."""

    def __init__(self, rules: List[BaseRule], strategy: DetectionStrategy = None):
        self.rules = list(rules)
        self.strategy = strategy or SequentialStrategy()

    def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.rules:
            LOGGER.debug("No hay reglas cargadas en el detector")
            return []

        try:
            results = self.strategy.run(self.rules, event)
        except Exception as exc:
            LOGGER.exception("Error ejecutando la estrategia de deteccion: %s", exc)
            results = []
            for rule in self.rules:
                try:
                    results.append(rule.evaluate(event))
                except Exception as rule_exc:
                    LOGGER.exception(
                        "Error evaluando regla %s: %s",
                        getattr(rule, "rule_id", "<no-id>"),
                        rule_exc,
                    )
                    results.append(
                        {
                            "rule_id": getattr(rule, "rule_id", None),
                            "name": getattr(rule, "name", None),
                            "severity": getattr(rule, "severity", "low"),
                            "matched": False,
                            "error": str(rule_exc),
                        }
                    )

        normalized = []
        for result in results:
            if isinstance(result, dict):
                normalized.append(result)
            else:
                normalized.append(
                    {
                        "rule_id": getattr(result, "rule_id", None),
                        "name": getattr(result, "name", None),
                        "matched": bool(getattr(result, "matched", False)),
                        "severity": getattr(result, "severity", "low"),
                        "metadata": getattr(result, "metadata", {}),
                    }
                )
        return normalized

    def evaluate_many(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [{"event": event, "results": self.evaluate(event)} for event in events]
