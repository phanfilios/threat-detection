# detector.py
# Funciones para procesar eventos y aplicar reglas

from rules import RULES

def detect_threats(event):
    """
    Analiza un evento y devuelve una lista de reglas que coinciden (potenciales amenazas).
    """
    matched_rules = []
    for rule in RULES:
        try:
            if rule['condition'](event):
                matched_rules.append(rule)
        except Exception as e:
            print(f"Error evaluando regla {rule['id']}: {e}")
    return matched_rules
