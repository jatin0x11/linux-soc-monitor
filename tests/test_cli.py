"""Command-line interface and output-file behavior."""

from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.main import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = PROJECT_ROOT / "sample_logs" / "auth.log"


def test_text_analysis_prints_report(capsys):
    code = main(["--file", str(SAMPLE), "--year", "2024", "--no-color"])
    assert code == 0
    output = capsys.readouterr().out
    assert "LINUX SOC MONITOR" in output
    assert "ALERTS (9)" in output
    assert "Input SHA-256:" in output


def test_json_report_written_to_file(tmp_path, capsys):
    destination = tmp_path / "report.json"
    code = main(
        [
            "--file",
            str(SAMPLE),
            "--year",
            "2024",
            "--format",
            "json",
            "--output",
            str(destination),
        ]
    )
    assert code == 0
    assert "JSON report written to" in capsys.readouterr().out
    report = json.loads(destination.read_text(encoding="utf-8"))
    assert report["summary"]["alerts_generated"] == 9
    assert report["report"]["parameters"]["failure_threshold"] == 5
    assert len(report["alerts"]) == 9


def test_json_report_to_stdout(capsys):
    code = main(
        [
            "--file",
            str(SAMPLE),
            "--year",
            "2024",
            "--format",
            "json",
            "--output",
            "-",
        ]
    )
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["alerts"][0]["alert_id"] == "ALT-0001"


def test_default_json_output_path(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "--file",
            str(SAMPLE),
            "--year",
            "2024",
            "--format",
            "json",
            "--quiet",
        ]
    )
    assert code == 0
    files = list((tmp_path / "reports").glob("soc_report_*.json"))
    assert len(files) == 1
    assert json.loads(files[0].read_text(encoding="utf-8"))["summary"][
        "alerts_generated"
    ] == 9


def test_csv_report_to_stdout(capsys):
    code = main(
        [
            "--file",
            str(SAMPLE),
            "--year",
            "2024",
            "--format",
            "csv",
            "--output",
            "-",
        ]
    )
    assert code == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert len(rows) == 9
    assert rows[0]["alert_id"] == "ALT-0001"
    assert rows[0]["severity"] == "High"


def test_text_report_written_to_file(tmp_path, capsys):
    destination = tmp_path / "nested" / "report.txt"
    code = main(
        [
            "--file",
            str(SAMPLE),
            "--year",
            "2024",
            "--output",
            str(destination),
            "--no-color",
        ]
    )
    assert code == 0
    assert destination.exists()
    assert "LINUX SOC MONITOR" in destination.read_text(encoding="utf-8")
    assert "Text report written to" in capsys.readouterr().out


def test_no_single_failures_option_removes_low_alerts(tmp_path):
    destination = tmp_path / "report.json"
    code = main(
        [
            "--file",
            str(SAMPLE),
            "--year",
            "2024",
            "--format",
            "json",
            "--output",
            str(destination),
            "--no-single-failures",
        ]
    )
    assert code == 0
    report = json.loads(destination.read_text(encoding="utf-8"))
    assert report["summary"]["alerts_by_severity"]["Low"] == 0
    assert report["summary"]["alerts_generated"] == 6


def test_custom_thresholds_are_reflected_in_report(tmp_path):
    destination = tmp_path / "report.json"
    code = main(
        [
            "--file",
            str(SAMPLE),
            "--year",
            "2024",
            "--format",
            "json",
            "--output",
            str(destination),
            "--threshold",
            "20",
            "--high-threshold",
            "30",
            "--window",
            "10",
        ]
    )
    assert code == 0
    report = json.loads(destination.read_text(encoding="utf-8"))
    parameters = report["report"]["parameters"]
    assert parameters["failure_threshold"] == 20
    assert parameters["high_volume_threshold"] == 30
    assert parameters["window_seconds"] == 600
    assert report["summary"]["alerts_by_severity"]["High"] == 0
    assert report["summary"]["alerts_by_severity"]["Medium"] == 3


def test_missing_input_file_returns_error(tmp_path, capsys):
    code = main(["--file", str(tmp_path / "missing.log")])
    assert code == 1
    assert "input file not found" in capsys.readouterr().err


def test_directory_as_input_returns_error(tmp_path, capsys):
    code = main(["--file", str(tmp_path)])
    assert code == 1
    assert "not a regular file" in capsys.readouterr().err


def test_invalid_threshold_combination_is_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--file",
                str(SAMPLE),
                "--threshold",
                "10",
                "--high-threshold",
                "5",
            ]
        )
    assert exc.value.code == 2
    assert "high-threshold" in capsys.readouterr().err


def test_non_finite_window_is_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--file", str(SAMPLE), "--window", "nan"])
    assert exc.value.code == 2
    assert "finite number" in capsys.readouterr().err


def test_unknown_timezone_returns_error(capsys):
    code = main(["--file", str(SAMPLE), "--assume-tz", "Not/AZone"])
    assert code == 1
    assert "unknown timezone" in capsys.readouterr().err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "linux-soc-monitor 1.0.0" in capsys.readouterr().out


def test_module_entry_point_runs_the_analyzer():
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "app",
            "--file",
            str(SAMPLE),
            "--year",
            "2024",
            "--format",
            "json",
            "--output",
            "-",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["summary"]["alerts_generated"] == 9
