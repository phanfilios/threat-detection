import logging
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from src.rules.base_rule import BaseRule

LOGGER = logging.getLogger(__name__)


class DetectionStrategy(ABC):
    """Interfaz para estrategias de deteccion."""

    @abstractmethod
    def run(self, rules: List[BaseRule], event: Dict[str, Any]) -> List[Dict[str, Any]]:
        raise NotImplementedError


class SequentialStrategy(DetectionStrategy):
    """Estrategia simple, ideal para debugging y resultados ordenados."""

    def run(self, rules: List[BaseRule], event: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = []
        for rule in rules:
            try:
                results.append(rule.evaluate(event))
            except Exception as exc:
                LOGGER.exception("Error evaluando regla %s: %s", getattr(rule, "rule_id", "<no-id>"), exc)
                results.append(
                    {
                        "rule_id": getattr(rule, "rule_id", None),
                        "name": getattr(rule, "name", None),
                        "severity": getattr(rule, "severity", "low"),
                        "matched": False,
                        "error": str(exc),
                    }
                )
        return results


class ThreadPoolStrategy(DetectionStrategy):
    """Evalua reglas en paralelo usando ThreadPoolExecutor."""

    def __init__(self, max_workers: int = None, stop_on_match: bool = False):
        self.max_workers = max_workers
        self.stop_on_match = stop_on_match

    def _eval_rule(self, rule: BaseRule, event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return rule.evaluate(event)
        except Exception as exc:
            LOGGER.exception("Error evaluando regla %s en hilo: %s", getattr(rule, "rule_id", "<no-id>"), exc)
            return {
                "rule_id": getattr(rule, "rule_id", None),
                "name": getattr(rule, "name", None),
                "severity": getattr(rule, "severity", "low"),
                "matched": False,
                "error": str(exc),
            }

    def run(self, rules: List[BaseRule], event: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = []
        if not rules:
            return results

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_rule = {executor.submit(self._eval_rule, rule, event): rule for rule in rules}
            try:
                for future in as_completed(future_to_rule):
                    result = future.result()
                    results.append(result)
                    if self.stop_on_match and result.get("matched"):
                        LOGGER.debug("Regla %s hizo match; cancelando tareas pendientes", result.get("rule_id"))
                        for pending in future_to_rule:
                            if not pending.done():
                                pending.cancel()
                        break
            except Exception as exc:
                LOGGER.exception("Error en ejecucion paralela de reglas: %s", exc)
                for future in future_to_rule:
                    if future.done() and not future.cancelled():
                        try:
                            results.append(future.result())
                        except Exception:
                            pass
        return results
