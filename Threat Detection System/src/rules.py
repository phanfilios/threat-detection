# rules.py
# Definir las reglas de deteccion de amenazaas

# Ejemplo de reglas basadas en patrones o condiciones 

RULES = [
     {
        'id': 'R001',
        'description': 'Detección de múltiples intentos fallidos de login',
        'condition': lambda event: event['type'] == 'login_failure' and event['attempts'] >= 5
    },
    {
        'id': 'R002',
        'description': 'Acceso a archivos confidenciales sin autorización',
        'condition': lambda event: event['type'] == 'file_access' and event['file'] in ['confidential_report.pdf', 'financials.xlsx'] and not event['authorized']
    },
    {
        'id': 'R003',
        'description': 'Actividad sospechosa en horas fuera de horario laboral',
        'condition': lambda event: event['type'] == 'user_activity' and event['timestamp'].hour < 8 or event['timestamp'].hour > 18
    }
]