"""Report generation for text, JSON, and CSV outputs."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from app.detector import Detector
from app.log_parser import LogParser
from app.reporter import build_report, render_text, write_csv, write_json

SAMPLE = Path(__file__).resolve().parents[1] / "sample_logs" / "auth.log"


def analyzed_report():
    parse_result = LogParser(year=2024).parse_file(SAMPLE)
    detection = Detector().detect(parse_result.events)
    report = build_report(
        parse_result=parse_result,
        detection=detection,
        input_path=str(SAMPLE),
        analyzed_at=datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        duration_ms=12,
        input_sha256="deadbeef",
        detection_parameters={
            "failure_threshold": 5,
            "high_volume_threshold": 10,
            "window_seconds": 300,
            "window_minutes": 5.0,
            "single_failure_alerts": True,
        },
    )
    return parse_result, detection, report


def test_report_metadata_and_summary():
    _, detection, report = analyzed_report()
    meta = report["report"]
    assert meta["tool"] == "Linux SOC Monitor"
    assert meta["generated_at"] == "2024-03-01T12:00:00Z"
    assert meta["input_file"] == str(SAMPLE)
    assert meta["input_sha256"] == "deadbeef"
    assert meta["parameters"]["failure_threshold"] == 5
    assert "not proof of compromise" in meta["disclaimer"]

    summary = report["summary"]
    assert summary["alerts_generated"] == len(detection.alerts)
    assert summary["failed_logins"] == 21
    assert summary["successful_logins"] == 5
    assert summary["unparsed_lines"] == 2
    assert summary["pam_duplicates_removed"] == 1
    assert summary["invalid_user_attempts"] == 3
    assert summary["alerts_by_severity"] == {"High": 2, "Medium": 4, "Low": 3}
    assert summary["first_event_timestamp"] == "2024-01-15T08:00:04Z"
    assert summary["last_event_timestamp"] == "2024-01-15T10:06:00Z"
    assert summary["skipped_events_missing_fields"] == 1


def test_alert_dict_contains_triage_fields_and_evidence():
    _, _, report = analyzed_report()
    alert = report["alerts"][0]
    assert alert["alert_id"] == "ALT-0001"
    assert alert["rule_id"] == "R005"
    assert alert["severity"] == "High"
    assert alert["source_ip"] == "203.0.113.45"
    assert alert["reason"]
    assert alert["analyst_action"]
    assert alert["mitre_attack"]
    assert alert["evidence_count"] == len(alert["evidence"])
    assert alert["evidence"][0]["raw"].startswith("Jan 15 09:00:01")
    assert alert["evidence"][0]["timestamp"] == "2024-01-15T09:00:01Z"


def test_json_output_is_serializable_and_round_trips():
    _, _, report = analyzed_report()
    stream = io.StringIO()
    write_json(report, stream)
    decoded = json.loads(stream.getvalue())
    assert decoded["summary"] == report["summary"]
    assert decoded["alerts"] == report["alerts"]
    assert len(decoded["sources"]) == 8


def test_csv_output_has_expected_fields_and_rows():
    _, _, report = analyzed_report()
    stream = io.StringIO()
    write_csv(report, stream)
    rows = list(csv.DictReader(io.StringIO(stream.getvalue())))
    assert len(rows) == len(report["alerts"])
    assert rows[0]["alert_id"] == "ALT-0001"
    assert rows[0]["rule_id"] == "R005"
    assert rows[0]["severity"] == "High"
    assert "T1078" in rows[0]["mitre_attack"]
    assert "Failed password" in rows[0]["evidence"]
    assert int(rows[0]["evidence_count"]) == rows[0]["evidence"].count(" | ") + 1


def test_text_output_contains_summary_alerts_and_notice():
    _, _, report = analyzed_report()
    text = render_text(report)
    assert "LINUX SOC MONITOR" in text
    assert "SUMMARY" in text
    assert "Alerts generated:" in text
    assert "ALERTS (9)" in text
    assert "[HIGH] Failure followed by successful login (R005)" in text
    assert "Analyst action:" in text
    assert "MITRE ATT&CK:" in text
    assert "Evidence (7 event(s)):" in text
    assert "NOTICE" in text
    assert "\033[" not in text


def test_text_output_supports_color_and_evidence_limits():
    _, _, report = analyzed_report()
    text = render_text(report, color=True, max_evidence=2)
    assert "\033[1;91m[HIGH]\033[0m" in text
    assert "more event(s); see the JSON report" in text


def test_text_output_escapes_control_characters_from_log_fields():
    _, _, report = analyzed_report()
    report["alerts"][0]["usernames"] = ["evil\x1b[31mname"]
    report["alerts"][0]["evidence"][0]["raw"] = "raw\x1b[2Jline"
    text = render_text(report)
    assert "\x1b" not in text
    assert "\\x1b[31mname" in text
    assert "raw\\x1b[2jline" in text.lower()


def test_csv_output_neutralizes_formula_like_usernames():
    _, _, report = analyzed_report()
    report["alerts"][0]["usernames"] = ["=HYPERLINK(\"http://example.invalid\")"]
    stream = io.StringIO()
    write_csv(report, stream)
    rows = list(csv.DictReader(io.StringIO(stream.getvalue())))
    assert rows[0]["usernames"].startswith("'=")


def test_text_output_with_no_alerts():
    report = {
        "report": {
            "input_file": "empty.log",
            "generated_at": "2024-03-01T12:00:00Z",
            "parameters": {
                "assumed_timezone": "UTC",
                "window_minutes": 5.0,
                "failure_threshold": 5,
                "high_volume_threshold": 10,
                "single_failure_alerts": True,
            },
            "input_sha256": None,
        },
        "summary": {
            "lines_read": 0,
            "events_parsed": 0,
            "failed_logins": 0,
            "successful_logins": 0,
            "invalid_user_attempts": 0,
            "non_auth_events": 0,
            "unparsed_lines": 0,
            "pam_duplicates_removed": 0,
            "skipped_events_missing_fields": 0,
            "unique_source_ips": 0,
            "alerts_generated": 0,
            "alerts_by_severity": {"High": 0, "Medium": 0, "Low": 0},
        },
        "alerts": [],
    }
    text = render_text(report)
    assert "No alerts were generated" in text
    assert "NOTICE" in text
