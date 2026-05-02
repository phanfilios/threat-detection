import ipaddress
import re
from typing import Any, Dict, List

from src.utils import get_nested_value

from .base_rule import BaseRule


class KeywordRule(BaseRule):
    """Busca palabras clave en un campo de texto del evento."""

    def matches(self, event: Dict[str, Any]) -> bool:
        field = self.config.get("field", "message")
        keywords = self.config.get("keywords", [])
        ignore_case = self.config.get("ignore_case", True)

        text = str(get_nested_value(event, field, ""))
        flags = re.IGNORECASE if ignore_case else 0

        return any(re.search(re.escape(keyword), text, flags) for keyword in keywords)

    def metadata(self, event: Dict[str, Any]) -> Dict[str, Any]:
        field = self.config.get("field", "message")
        text = str(get_nested_value(event, field, ""))
        flags = re.IGNORECASE if self.config.get("ignore_case", True) else 0
        hits = [
            keyword
            for keyword in self.config.get("keywords", [])
            if re.search(re.escape(keyword), text, flags)
        ]
        return {"field": field, "keywords_matched": hits}


class ThresholdRule(BaseRule):
    """Compara un valor numerico con un umbral."""

    OPERATORS = {
        ">": lambda a, b: a > b,
        "<": lambda a, b: a < b,
        ">=": lambda a, b: a >= b,
        "<=": lambda a, b: a <= b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }

    def matches(self, event: Dict[str, Any]) -> bool:
        field = self.config.get("field")
        threshold = self.config.get("threshold")
        operator = self.config.get("operator", ">")

        if field is None or threshold is None:
            raise ValueError("ThresholdRule requires 'field' and 'threshold' in config")

        value = get_nested_value(event, field)
        if value is None:
            return False

        try:
            value_num = float(value)
            threshold_num = float(threshold)
        except (TypeError, ValueError):
            return False

        op_func = self.OPERATORS.get(operator)
        if not op_func:
            raise ValueError(f"Unsupported operator {operator}")

        return op_func(value_num, threshold_num)

    def metadata(self, event: Dict[str, Any]) -> Dict[str, Any]:
        field = self.config.get("field")
        return {
            "field": field,
            "value": get_nested_value(event, field),
            "operator": self.config.get("operator", ">"),
            "threshold": self.config.get("threshold"),
        }


class RegexRule(BaseRule):
    """Evalua un patron regex contra un campo de texto."""

    def _compiled(self):
        pattern = self.config.get("pattern")
        if not pattern:
            raise ValueError("RegexRule requires 'pattern' in config")
        flags = re.IGNORECASE if self.config.get("ignore_case", True) else 0
        return re.compile(pattern, flags)

    def matches(self, event: Dict[str, Any]) -> bool:
        field = self.config.get("field", "message")
        return bool(self._compiled().search(str(get_nested_value(event, field, ""))))

    def metadata(self, event: Dict[str, Any]) -> Dict[str, Any]:
        field = self.config.get("field", "message")
        match = self._compiled().search(str(get_nested_value(event, field, "")))
        return {"field": field, "match": match.group(0) if match else None}


class FieldEqualsRule(BaseRule):
    """Comprueba que un campo sea igual a uno de los valores esperados."""

    def matches(self, event: Dict[str, Any]) -> bool:
        field = self.config.get("field")
        expected = self.config.get("value", self.config.get("values"))
        if field is None:
            raise ValueError("FieldEqualsRule requires 'field' in config")
        values: List[Any] = expected if isinstance(expected, list) else [expected]
        return get_nested_value(event, field) in values

    def metadata(self, event: Dict[str, Any]) -> Dict[str, Any]:
        field = self.config.get("field")
        return {"field": field, "value": get_nested_value(event, field)}


class CidrRule(BaseRule):
    """Detecta IPs dentro de rangos CIDR observados como riesgosos."""

    def matches(self, event: Dict[str, Any]) -> bool:
        field = self.config.get("field", "source.ip")
        cidrs = self.config.get("cidrs", [])
        value = get_nested_value(event, field)
        if not value:
            return False
        address = ipaddress.ip_address(str(value))
        return any(address in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)

    def metadata(self, event: Dict[str, Any]) -> Dict[str, Any]:
        field = self.config.get("field", "source.ip")
        value = get_nested_value(event, field)
        matches = []
        if value:
            address = ipaddress.ip_address(str(value))
            matches = [
                cidr
                for cidr in self.config.get("cidrs", [])
                if address in ipaddress.ip_network(cidr, strict=False)
            ]
        return {"field": field, "ip": value, "cidrs_matched": matches}
