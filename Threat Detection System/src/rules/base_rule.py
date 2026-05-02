from abc import ABC, abstractmethod
from typing import Any, Dict

from src.utils import utc_now_iso


class BaseRule(ABC):
    """Contrato base para reglas de deteccion."""

    def __init__(self, rule_id: str, name: str, config: Dict[str, Any] = None):
        if not rule_id:
            raise ValueError("Cada regla necesita un id unico")
        self.rule_id = rule_id
        self.name = name
        self.config = config or {}
        self.description = self.config.get("description", "")
        self.severity = str(self.config.get("severity", "low")).lower()
        self.enabled = bool(self.config.get("enabled", True))

    @abstractmethod
    def matches(self, event: Dict[str, Any]) -> bool:
        raise NotImplementedError

    def metadata(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return {}

    def evaluate(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return self._result(False, skipped=True)

        try:
            matched = self.matches(event)
        except Exception as exc:
            return self._result(False, error=str(exc))

        return self._result(matched, metadata=self.metadata(event) if matched else {})

    def _result(
        self,
        matched: bool,
        metadata: Dict[str, Any] = None,
        error: str = None,
        skipped: bool = False,
    ) -> Dict[str, Any]:
        result = {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "matched": matched,
            "metadata": metadata or {},
            "evaluated_at": utc_now_iso(),
        }
        if error:
            result["error"] = error
        if skipped:
            result["skipped"] = True
        return {
            key: value
            for key, value in result.items()
            if value not in (None, "", {}) or key in {"metadata", "matched"}
        }
