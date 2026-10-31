"""Build and render investigation reports as text, JSON, and CSV."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from typing import Optional, TextIO

from . import __version__
from .detector import DetectionResult
from .log_parser import EVENT_OTHER, ParseResult, format_timestamp


DISCLAIMER = (
    "Alerts are investigation leads, not proof of compromise. Validate every "
    "finding against the original log and surrounding activity. Source logs "
    "are treated as read-only evidence."
)

_SEVERITY_COLORS = {
    "High": "\033[1;91m",
    "Medium": "\033[1;93m",
    "Low": "\033[1;94m",
}
_RESET = "\033[0m"


def build_report(
    parse_result: ParseResult,
    detection: DetectionResult,
    input_path: str,
    analyzed_at: datetime,
    duration_ms: int,
    input_sha256: Optional[str] = None,
    detection_parameters: Optional[dict] = None,
) -> dict:
    """Assemble the report dictionary shared by all output formats."""
    stats = parse_result.stats
    timestamped = [e.timestamp for e in parse_result.events if e.timestamp]
    severity_counts = detection.alerts_by_severity()

    alert_rule_counts: dict[str, int] = {}
    for alert in detection.alerts:
        alert_rule_counts[alert.rule_id] = alert_rule_counts.get(alert.rule_id, 0) + 1

    summary = {
        "lines_read": stats.get("lines_read", 0),
        "blank_lines": stats.get("blank_lines", 0),
        "unparsed_lines": stats.get("unparsed_lines", 0),
        "events_parsed": len(parse_result.events),
        "non_auth_events": stats.get(
            "non_auth_events",
            sum(1 for e in parse_result.events if e.event_type == EVENT_OTHER),
        ),
        "pam_duplicates_removed": stats.get("pam_duplicates_removed", 0),
        "failed_logins": detection.failures_analyzed,
        "successful_logins": detection.successes_analyzed,
        "invalid_user_attempts": detection.invalid_user_attempts,
        "unique_source_ips": len(detection.sources),
        "alerts_generated": len(detection.alerts),
        "alerts_by_severity": severity_counts,
        "alerts_by_rule": alert_rule_counts,
        "skipped_events_missing_fields": detection.skipped_events_missing_fields,
        "first_event_timestamp": format_timestamp(min(timestamped))
        if timestamped
        else None,
        "last_event_timestamp": format_timestamp(max(timestamped))
        if timestamped
        else None,
        "analysis_duration_ms": duration_ms,
    }

    parameters = {
        "failure_threshold": None,
        "high_volume_threshold": None,
        "window_seconds": None,
        "window_minutes": None,
        "single_failure_alerts": None,
        "assumed_timezone": parse_result.assumed_timezone,
    }
    if detection_parameters:
        parameters.update(detection_parameters)

    return {
        "report": {
            "tool": "Linux SOC Monitor",
            "version": __version__,
            "generated_at": format_timestamp(analyzed_at),
            "input_file": input_path,
            "input_sha256": input_sha256,
            "input_format": "Linux authentication log / exported journalctl text",
            "parameters": parameters,
            "disclaimer": DISCLAIMER,
        },
        "summary": summary,
        "alerts": [alert.to_dict() for alert in detection.alerts],
        "sources": detection.sources,
        "parser_diagnostics": {
            "unparsed_reasons": stats.get("unparsed_reasons", {}),
            "unsupported_samples": parse_result.unsupported_samples,
        },
    }


def _format_count(value: int) -> str:
    return f"{value:,}"


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _safe_text(value: str) -> str:
    """Escape control characters before writing log-derived text to a TTY.

    Log fields are attacker-influenced.  Without this, a crafted username or
    message could emit terminal escape sequences while an analyst reviews a
    report.  The original text remains available unchanged in JSON evidence.
    """
    return _CONTROL_CHARS.sub(lambda match: f"\\x{ord(match.group()):02x}", value)


def _csv_safe(value: str) -> str:
    """Reduce CSV formula injection in user-controlled columns."""
    if value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _severity_tag(severity: str, color: bool) -> str:
    tag = f"[{severity.upper()}]"
    if not color:
        return tag
    return f"{_SEVERITY_COLORS.get(severity, '')}{tag}{_RESET}"


def _shorten(text: str, limit: int = 240) -> str:
    text = text.rstrip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _evidence_line(event: dict) -> str:
    fields = [f"event={event['event_type']}"]
    if event.get("username"):
        fields.append(f"user={_safe_text(event['username'])}")
    if event.get("source_ip"):
        fields.append(f"ip={event['source_ip']}")
    if event.get("port") is not None:
        fields.append(f"port={event['port']}")
    timestamp = event.get("timestamp") or event.get("timestamp_raw") or "no timestamp"
    return f"{timestamp} {' '.join(fields)}"


def render_text(report: dict, color: bool = False, max_evidence: int = 8) -> str:
    """Render a human-readable terminal report."""
    meta = report["report"]
    summary = report["summary"]
    parameters = meta.get("parameters", {})
    alerts = report["alerts"]

    lines: list[str] = []
    lines.append("LINUX SOC MONITOR")
    lines.append("=================")
    lines.append(f"Input file: {_safe_text(str(meta.get('input_file')))}")
    if meta.get("input_sha256"):
        lines.append(f"Input SHA-256: {meta['input_sha256']}")
    lines.append(f"Analyzed at: {meta.get('generated_at')} (UTC)")
    lines.append(
        f"Assumed timezone for offset-less timestamps: "
        f"{parameters.get('assumed_timezone', 'UTC')}"
    )
    lines.append("")

    lines.append("SUMMARY")
    lines.append("-------")
    rows = [
        ("Lines read", summary["lines_read"]),
        ("Events parsed", summary["events_parsed"]),
        ("  Failed logins", summary["failed_logins"]),
        ("  Successful logins", summary["successful_logins"]),
        ("  Invalid-user attempts", summary["invalid_user_attempts"]),
        ("  Non-auth lines", summary["non_auth_events"]),
        ("Unparsed lines", summary["unparsed_lines"]),
        ("PAM duplicate lines removed", summary["pam_duplicates_removed"]),
        (
            "Skipped events (missing fields)",
            summary["skipped_events_missing_fields"],
        ),
        ("Unique source IPs", summary["unique_source_ips"]),
    ]
    for label, value in rows:
        lines.append(f"{label + ':':<34}{_format_count(value)}")

    severity = summary["alerts_by_severity"]
    lines.append(
        f"{'Alerts generated:':<34}{summary['alerts_generated']} "
        f"(High {severity.get('High', 0)}, Medium {severity.get('Medium', 0)}, "
        f"Low {severity.get('Low', 0)})"
    )
    if summary.get("first_event_timestamp"):
        lines.append(
            f"{'Observation window:':<34}"
            f"{summary['first_event_timestamp']} to "
            f"{summary['last_event_timestamp']}"
        )
    if parameters.get("window_minutes") is not None:
        lines.append(
            f"{'Detection settings:':<34}"
            f"failure>={parameters.get('failure_threshold')}, "
            f"high>={parameters.get('high_volume_threshold')}, "
            f"window={parameters.get('window_minutes'):g} min, "
            f"single-failure alerts="
            f"{'on' if parameters.get('single_failure_alerts') else 'off'}"
        )
    lines.append("")

    if not alerts:
        lines.append("ALERTS")
        lines.append("------")
        lines.append(
            "No alerts were generated with the configured thresholds and window."
        )
    else:
        alerts_heading = f"ALERTS ({len(alerts)})"
        lines.append(alerts_heading)
        lines.append("-" * len(alerts_heading))
        for alert in alerts:
            lines.append(
                f"{_severity_tag(alert['severity'], color)} {alert['rule_name']} "
                f"({alert['rule_id']})"
            )
            lines.append(f"  Alert ID: {alert['alert_id']}")
            lines.append(f"  Source IP: {alert['source_ip'] or 'unknown'}")
            lines.append(
                "  Username(s): "
                + (
                    ", ".join(_safe_text(name) for name in alert["usernames"])
                    if alert["usernames"]
                    else "unknown"
                )
            )
            if alert.get("window_start") and alert.get("window_end"):
                lines.append(
                    f"  Window: {alert['window_start']} to {alert['window_end']}"
                )
            lines.append(f"  Reason: {alert['reason']}")
            lines.append(f"  Analyst action: {alert['analyst_action']}")
            if alert["mitre_attack"]:
                technique_text = "; ".join(
                    f"{item['technique_id']} {item['technique_name']}"
                    for item in alert["mitre_attack"]
                )
                lines.append(f"  MITRE ATT&CK: {technique_text}")

            evidence = alert["evidence"]
            lines.append(f"  Evidence ({len(evidence)} event(s)):")
            for event in evidence[:max_evidence]:
                lines.append(f"    - {_evidence_line(event)}")
                lines.append(f"      {_shorten(_safe_text(event['raw']))}")
            if len(evidence) > max_evidence:
                lines.append(
                    f"    ... {len(evidence) - max_evidence} more event(s); see the "
                    "JSON report for complete evidence."
                )
            lines.append("")

    lines.append("NOTICE")
    lines.append("------")
    lines.append(
        "Alerts are triage leads, not proof of compromise. Validate each alert"
    )
    lines.append(
        "against the original log and surrounding activity. Source logs were"
    )
    lines.append("not modified.")
    return "\n".join(lines).rstrip() + "\n"


def write_json(report: dict, stream: TextIO) -> None:
    """Serialize a report as indented JSON."""
    json.dump(report, stream, indent=2, ensure_ascii=False)
    stream.write("\n")


CSV_FIELDS = [
    "alert_id",
    "rule_id",
    "rule_name",
    "severity",
    "timestamp",
    "source_ip",
    "usernames",
    "failure_count",
    "window_start",
    "window_end",
    "mitre_attack",
    "reason",
    "analyst_action",
    "evidence_count",
    "evidence",
]


def write_csv(report: dict, stream: TextIO) -> None:
    """Write one row per alert, including full supporting evidence."""
    writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for alert in report["alerts"]:
        writer.writerow(
            {
                "alert_id": alert["alert_id"],
                "rule_id": alert["rule_id"],
                "rule_name": alert["rule_name"],
                "severity": alert["severity"],
                "timestamp": alert["timestamp"],
                "source_ip": alert["source_ip"],
                "usernames": _csv_safe("; ".join(alert["usernames"])),
                "failure_count": alert["failure_count"],
                "window_start": alert["window_start"],
                "window_end": alert["window_end"],
                "mitre_attack": "; ".join(
                    f"{item['technique_id']} {item['technique_name']}"
                    for item in alert["mitre_attack"]
                ),
                "reason": alert["reason"],
                "analyst_action": alert["analyst_action"],
                "evidence_count": len(alert["evidence"]),
                "evidence": " | ".join(
                    event["raw"].replace("\r", " ").replace("\n", " ")
                    for event in alert["evidence"]
                ),
            }
        )
