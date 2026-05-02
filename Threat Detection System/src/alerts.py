# alerts.py
# Funciones para generar y gestionar alertas

def generate_alert(event, matched_rules):
    """
    Crea una alerta basada en el evento y las reglas coincidentes.
    """
    alert = {
        'event_id': event.get('id'),
        'timestamp': event.get('timestamp'),
        'rules_triggered': [rule['id'] for rule in matched_rules],
        'description': 'Alerta de amenaza detectada',
        'details': {
            'event': event,
            'rules': matched_rules
        }
    }
    return alert

def send_alert(alert):
    """
    Envía la alerta a un sistema de monitoreo o registra la alerta.
    """
    # Aquí puedes integrar con un sistema de notificación, logging, etc.
    print(f"ALERTA: Se ha detectado una amenaza - Reglas: {alert['rules_triggered']}")
    # Por ejemplo, guardar en un archivo o enviarlo a un API
