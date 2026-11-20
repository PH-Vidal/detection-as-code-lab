"""Unified CLI for the Detection-as-Code & Purple Team SOC Lab (`dac-lab`)."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from detection_engine import __version__
from detection_engine.enricher import IOCEnricher
from detection_engine.models import DetectionReport
from detection_engine.normalizer import load_events_from_paths
from detection_engine.reporter import (
    format_terminal_report,
    send_discord_alert,
    write_json_report,
    write_markdown_report,
)
from detection_engine.sigma_engine import (
    SigmaDetectionEngine,
    SigmaValidationError,
    load_rules_from_dir,
)
from simulator.attack_simulator import SCENARIOS, generate_lab_logs

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_TI_FEED = PROJECT_ROOT / "threat_intel" / "ioc_feed.json"


def _cmd_validate_rules(args: argparse.Namespace) -> int:
    try:
        rules = load_rules_from_dir(args.rules)
    except (FileNotFoundError, SigmaValidationError, ValueError) as exc:
        print(f"[ERROR] Rule validation failed: {exc}", file=sys.stderr)
        return 1

    print(f"[OK] Validated {len(rules)} Sigma rules in {args.rules}:")
    for rule in rules:
        mitre = ", ".join(rule.mitre_techniques) or "N/A"
        print(f"  - [{rule.level.upper():8}] {rule.title} ({mitre})")
    return 0


def _cmd_simulate(args: argparse.Namespace) -> int:
    output_dir = Path(args.output)
    generated = generate_lab_logs(output_dir, scenario=args.scenario, include_benign=not args.no_benign)
    print(f"[OK] Generated synthetic telemetry in {output_dir} (scenario={args.scenario}):")
    for log_name, path in generated.items():
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        print(f"  - {log_name:12}: {path} ({line_count} events)")
    return 0


def _run_detection(
    *,
    log_paths: list[str | Path],
    rules_dir: str | Path,
    ti_feed_path: str | Path | None,
    log_type: str = "auto",
    json_out: str | None = None,
    markdown_out: str | None = None,
    discord_webhook: str | None = None,
    fail_on_alert: bool = False,
) -> int:
    rules = load_rules_from_dir(rules_dir)
    events, resolved_files = load_events_from_paths(log_paths, log_type=log_type)

    engine = SigmaDetectionEngine(rules)
    alerts = engine.evaluate(events)

    if ti_feed_path and Path(ti_feed_path).is_file():
        enricher = IOCEnricher.from_file(ti_feed_path)
        alerts = enricher.enrich_alerts(alerts)

    report = DetectionReport(
        generated_at=datetime.now(UTC).isoformat(),
        rules_loaded=len(rules),
        events_processed=len(events),
        alerts=alerts,
        log_files=resolved_files,
    )

    print(format_terminal_report(report))

    if json_out:
        saved = write_json_report(report, json_out)
        print(f"[OK] JSON report written to: {saved}")

    if markdown_out:
        saved_md = write_markdown_report(report, markdown_out)
        print(f"[OK] Markdown triage report written to: {saved_md}")

    webhook = discord_webhook or os.environ.get("DISCORD_WEBHOOK_URL")
    if webhook and alerts:
        status = send_discord_alert(report, webhook)
        print(f"[OK] Discord alert dispatched (HTTP {status}).")

    if fail_on_alert and alerts:
        return 2
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    return _run_detection(
        log_paths=args.logs,
        rules_dir=args.rules,
        ti_feed_path=args.ti_feed,
        log_type=args.log_type,
        json_out=args.json_out,
        markdown_out=args.markdown_out,
        discord_webhook=args.discord_webhook,
        fail_on_alert=args.fail_on_alert,
    )


def _cmd_run_lab(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir)
    logs_dir = out_dir / "logs"
    generate_lab_logs(logs_dir, scenario=args.scenario, include_benign=True)
    return _run_detection(
        log_paths=[logs_dir],
        rules_dir=args.rules,
        ti_feed_path=args.ti_feed,
        json_out=str(out_dir / "alerts.json"),
        markdown_out=str(out_dir / "incident_triage.md"),
        discord_webhook=args.discord_webhook,
        fail_on_alert=False,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dac-lab",
        description="Detection-as-Code & Purple Team SOC Lab (Sigma + Correlation + IOC Enrichment).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # validate-rules
    p_val = sub.add_parser("validate-rules", help="Validate all Sigma YAML rules in a directory.")
    p_val.add_argument("--rules", default=str(DEFAULT_RULES_DIR), help="Path to Sigma rules directory.")
    p_val.set_defaults(func=_cmd_validate_rules)

    # simulate
    p_sim = sub.add_parser("simulate", help="Generate synthetic attack + benign telemetry logs.")
    p_sim.add_argument(
        "--scenario",
        choices=["all", *SCENARIOS],
        default="all",
        help="Attack scenario to simulate.",
    )
    p_sim.add_argument("--output", default="lab_output/logs", help="Output directory for logs.")
    p_sim.add_argument("--no-benign", action="store_true", help="Exclude benign baseline traffic.")
    p_sim.set_defaults(func=_cmd_simulate)

    # detect
    p_det = sub.add_parser("detect", help="Run Sigma rules and IOC enrichment against log files.")
    p_det.add_argument("--logs", nargs="+", required=True, help="Log files or directories to inspect.")
    p_det.add_argument("--rules", default=str(DEFAULT_RULES_DIR), help="Path to Sigma rules directory.")
    p_det.add_argument("--ti-feed", default=str(DEFAULT_TI_FEED), help="Path to Threat Intel JSON feed.")
    p_det.add_argument(
        "--log-type",
        choices=["auto", "sshd", "webserver", "linux_audit"],
        default="auto",
        help="Log parser format (defaults to auto-detection).",
    )
    p_det.add_argument("--json-out", help="Write structured JSON report to this path.")
    p_det.add_argument("--markdown-out", help="Write Markdown triage report to this path.")
    p_det.add_argument("--discord-webhook", help="Optional Discord Webhook URL for alert delivery.")
    p_det.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="Exit with code 2 if one or more alerts are triggered.",
    )
    p_det.set_defaults(func=_cmd_detect)

    # run-lab
    p_lab = sub.add_parser(
        "run-lab",
        help="End-to-end run: simulate attacks, evaluate Sigma rules, enrich IOCs, and export reports.",
    )
    p_lab.add_argument("--scenario", choices=["all", *SCENARIOS], default="all")
    p_lab.add_argument("--output-dir", default="lab_output", help="Directory for logs and reports.")
    p_lab.add_argument("--rules", default=str(DEFAULT_RULES_DIR), help="Path to Sigma rules directory.")
    p_lab.add_argument("--ti-feed", default=str(DEFAULT_TI_FEED), help="Path to Threat Intel JSON feed.")
    p_lab.add_argument("--discord-webhook", help="Optional Discord Webhook URL.")
    p_lab.set_defaults(func=_cmd_run_lab)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
