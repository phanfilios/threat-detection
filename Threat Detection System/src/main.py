import argparse
import logging
import sys
from typing import List

from src.alerts import AlertManager, ConsoleNotifier, FileNotifier
from src.correlation import Correlator
from src.detector.detection_strategy import SequentialStrategy, ThreadPoolStrategy
from src.detector.detector import Detector
from src.rules.rule_loader import RuleLoader
from src.utils import (
    default_report_path,
    load_events_from_jsonl,
    pretty_print_results,
    setup_logging,
    severity_rank,
    utc_now_iso,
    write_html_report,
    write_json_report,
)

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Orquestador del detector de amenazas")
    parser.add_argument("--rules-dir", default="data/rules", help="Directorio de reglas JSON/YAML.")
    parser.add_argument("--events-file", default="data/events.jsonl", help="Archivo JSONL con eventos.")
    parser.add_argument("--strategy", choices=["sequential", "threaded"], default="sequential")
    parser.add_argument("--workers", type=int, default=None, help="Hilos para la estrategia threaded.")
    parser.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low")
    parser.add_argument("--correlation-window", type=int, default=10, help="Ventana temporal en minutos.")
    parser.add_argument("--failed-login-threshold", type=int, default=3, help="Fallos antes de alertar fuerza bruta.")
    parser.add_argument("--disable-correlation", action="store_true", help="Desactiva correlacion temporal.")
    parser.add_argument("--report-format", choices=["json", "html"], default="html")
    parser.add_argument("--output", help="Ruta del reporte. Si se omite, se crea en reports/.")
    parser.add_argument("--alerts-file", default="reports/alerts.jsonl", help="Archivo JSONL de alertas.")
    parser.add_argument("--fail-on-alert", action="store_true", help="Devuelve codigo 1 si hay alertas.")
    parser.add_argument("--verbose", action="store_true", help="Habilita logging detallado.")
    return parser


def parse_args():
    return build_parser().parse_args()


def main(argv: List[str] = None):
    args = parse_args() if argv is None else parse_args_from_list(argv)
    setup_logging(verbose=args.verbose)
    LOGGER.info("Iniciando orquestador del detector")

    loader = RuleLoader(rules_dir=args.rules_dir)
    try:
        rules = loader.load_all()
    except Exception as exc:
        LOGGER.exception("Error cargando reglas: %s", exc)
        return 2

    LOGGER.info("Reglas cargadas: %d", len(rules))

    strategy = (
        ThreadPoolStrategy(max_workers=args.workers)
        if args.strategy == "threaded"
        else SequentialStrategy()
    )
    detector = Detector(rules=rules, strategy=strategy)
    alert_manager = AlertManager(min_severity=args.min_severity)
    correlator = Correlator(
        window_minutes=args.correlation_window,
        failed_login_threshold=args.failed_login_threshold,
    )
    console_notifier = ConsoleNotifier()
    file_notifier = FileNotifier(args.alerts_file)

    try:
        events = load_events_from_jsonl(args.events_file)
    except Exception as exc:
        LOGGER.exception("Error cargando eventos: %s", exc)
        return 3

    LOGGER.info("Eventos cargados: %d", len(events))

    all_results = []
    all_alerts = []
    for index, event in enumerate(events):
        LOGGER.debug("Evaluando evento %d: %s", index, event.get("id", "<no-id>"))
        results = detector.evaluate(event)
        alerts = alert_manager.build_alerts(event, results)
        if not args.disable_correlation:
            alerts.extend(correlator.process_event(event, results))
        all_results.append({"event": event, "results": results})
        all_alerts.extend(alerts)
        pretty_print_results(event, results)
        console_notifier.send(alerts)
        file_notifier.send(alerts)

    report = build_report(all_results, all_alerts, len(rules))
    output = args.output or default_report_path(args.report_format)
    if args.report_format == "json":
        write_json_report(output, report)
    else:
        write_html_report(output, report)

    LOGGER.info("Deteccion completada. Eventos: %d | Alertas: %d", len(all_results), len(all_alerts))
    LOGGER.info("Reporte generado: %s", output)
    if args.fail_on_alert and all_alerts:
        return 1
    return 0


def build_report(all_results, all_alerts, rules_loaded: int):
    high_priority = [
        alert
        for alert in all_alerts
        if severity_rank(alert.get("severity")) >= severity_rank("high")
    ]
    return {
        "generated_at": utc_now_iso(),
        "summary": {
            "rules_loaded": rules_loaded,
            "events_processed": len(all_results),
            "alerts_total": len(all_alerts),
            "high_priority_alerts": len(high_priority),
        },
        "alerts": all_alerts,
        "events": all_results,
    }


def parse_args_from_list(argv: List[str]):
    return build_parser().parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
