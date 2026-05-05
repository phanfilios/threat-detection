# Threat Detection System

Sistema modular para detectar amenazas en eventos JSONL usando reglas declarativas en JSON o YAML. El proyecto esta pensado como una base profesional, ligera y extensible: reglas separadas, estrategias de deteccion, alertas y reportes minimalistas.

<img width="686" height="821" alt="image" src="https://github.com/user-attachments/assets/4ba89212-5568-4009-92eb-a9cd70b10754" />


## COMANDO RAPIDO 

python -m src.main --report-format json --output reports/realistic-report.json

## Caracteristicas

- Carga de reglas desde `data/rules` en YAML o JSON.
- Reglas incluidas: keywords, umbrales numericos, regex, igualdad de campos y rangos CIDR.
- Soporte para campos anidados con notacion tipo `source.ip` o `http.status_code`.
- Estrategia secuencial o paralela con `ThreadPoolExecutor`.
- Alertas priorizadas por severidad: `low`, `medium`, `high`, `critical`.
- Correlacion temporal para detectar patrones entre eventos.
- Reportes `HTML` minimalistas o `JSON` para integracion.

## Instalacion

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Uso rapido

```powershell
python -m src.main --rules-dir data/rules --events-file data/events.jsonl --report-format html --verbose
```

El reporte se genera automaticamente en `reports/` y las alertas se guardan en `reports/alerts.jsonl`.

## Ejemplos utiles

Ejecutar en paralelo:

```powershell
python -m src.main --strategy threaded --workers 4
```

Generar reporte JSON:

```powershell
python -m src.main --report-format json --output reports/report.json
```

Filtrar alertas desde severidad alta:

```powershell
python -m src.main --min-severity high
```

Usar correlacion temporal:

```powershell
python -m src.main --correlation-window 10 --failed-login-threshold 3
```

Patrones de correlacion incluidos:

- Posible fuerza bruta por multiples fallos de autenticacion desde la misma IP y usuario.
- Login exitoso despues de fallos recientes.
- Evento de alto riesgo seguido por proceso sospechoso desde la misma fuente.

## Formato de regla

```yaml
rules:
  - id: web-001
    name: SQL injection pattern
    type: regex
    severity: critical
    description: Detecta patrones comunes de SQL injection en la URL.
    config:
      field: url.path
      pattern: "(union\\s+select|or\\s+1=1|drop\\s+table)"
      ignore_case: true
```

## Estructura

```text
data/rules/       Reglas declarativas
reports/          Reportes y alertas generadas
src/rules/        Motor y clases de reglas
src/detector/     Estrategias y orquestador de deteccion
src/alerts/       Gestion y notificacion de alertas
src/main.py       CLI principal
```

## Siguientes mejoras recomendadas

- Agregar pruebas unitarias con `pytest`.
- Conectar `FileNotifier` a correo, Slack o una API SIEM.
- Agregar enriquecimiento de IPs o reputacion externa.
- Crear una interfaz web ligera si quieres visualizar eventos en tiempo real.
