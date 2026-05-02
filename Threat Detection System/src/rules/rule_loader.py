import json
import logging
import os
from importlib import import_module
from typing import Any, Dict, List

try:
    import yaml
except ModuleNotFoundError:
    yaml = None

LOGGER = logging.getLogger(__name__)

_RULE_CLASS_MAP = {
    "keyword": "src.rules.specific_rules.KeywordRule",
    "threshold": "src.rules.specific_rules.ThresholdRule",
    "regex": "src.rules.specific_rules.RegexRule",
    "field_equals": "src.rules.specific_rules.FieldEqualsRule",
    "cidr": "src.rules.specific_rules.CidrRule",
}


def _resolve_class(path: str):
    if ":" in path:
        module_path, class_name = path.split(":", 1)
    else:
        *module_parts, class_name = path.split(".")
        module_path = ".".join(module_parts)
    module = import_module(module_path)
    return getattr(module, class_name)


class RuleLoader:
    """Carga reglas JSON/YAML desde disco y valida definiciones minimas."""

    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir

    def load_from_file(self, filepath: str) -> Any:
        _, ext = os.path.splitext(filepath)
        with open(filepath, "r", encoding="utf-8") as handle:
            if ext.lower() in [".yml", ".yaml"]:
                if yaml is None:
                    raise RuntimeError("PyYAML no esta instalado. Ejecuta: pip install -r requirements.txt")
                return yaml.safe_load(handle) or {}
            if ext.lower() == ".json":
                return json.load(handle)
        raise ValueError("Unsupported rule file format: " + ext)

    def load_all(self) -> List:
        if not self.rules_dir:
            raise ValueError("rules_dir not set")
        if not os.path.isdir(self.rules_dir):
            raise FileNotFoundError(f"Rules directory not found: {self.rules_dir}")

        rules = []
        for filename in sorted(os.listdir(self.rules_dir)):
            path = os.path.join(self.rules_dir, filename)
            if not os.path.isfile(path):
                continue
            try:
                data = self.load_from_file(path)
            except ValueError:
                continue
            except Exception as exc:
                LOGGER.warning("No se pudo cargar %s: %s", path, exc)
                continue

            if isinstance(data, list):
                rules.extend(data)
            elif isinstance(data, dict):
                rules.extend(data.get("rules", [data]))
            else:
                LOGGER.warning("Formato de reglas no soportado en %s", path)

        return [self._instantiate_rule(rule) for rule in rules]

    def _instantiate_rule(self, rule_def: Dict[str, Any]):
        rule_id = rule_def.get("id") or rule_def.get("rule_id")
        name = rule_def.get("name", rule_id)
        config = {
            "description": rule_def.get("description", ""),
            "severity": rule_def.get("severity", "low"),
            "enabled": rule_def.get("enabled", True),
            **(rule_def.get("config", {}) or {}),
        }

        class_path = rule_def.get("class")
        if not class_path:
            rule_type = rule_def.get("type")
            class_path = _RULE_CLASS_MAP.get(rule_type)

        if not class_path:
            raise ValueError(f"Cannot determine class for rule {rule_id}")

        cls = _resolve_class(class_path)
        return cls(rule_id=rule_id, name=name, config=config)
