"""Command-line entry point for Linux SOC Monitor."""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from .detector import Detector, DetectionConfig
from .log_parser import LogParser
from .reporter import build_report, render_text, write_csv, write_json


DEFAULT_THRESHOLD = 5
DEFAULT_HIGH_THRESHOLD = 10
DEFAULT_WINDOW_MINUTES = 5.0
DEFAULT_TIMEZONE = "UTC"


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError(
            "must be a finite number greater than zero"
        )
    return parsed


def _year(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a four-digit year") from exc
    if not 1970 <= parsed <= 9999:
        raise argparse.ArgumentTypeError("must be between 1970 and 9999")
    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linux-soc-monitor",
        description=(
            "Analyze Linux authentication logs for suspicious SSH login "
            "patterns and produce triage reports."
        ),
        epilog=(
            "Examples:\n"
            "  python3 -m app.main --file sample_logs/auth.log\n"
            "  python3 -m app.main --file sample_logs/auth.log --format json\n"
            "  python3 -m app.main --file sample_logs/auth.log --format csv "
            "--output reports/findings.csv\n"
            "  python3 -m app.main --file sample_logs/auth.log --threshold 3 "
            "--window 10"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--file",
        "-f",
        required=True,
        metavar="PATH",
        help=(
            "authentication log to analyze (auth.log, /var/log/secure, or an "
            "exported journalctl text file)"
        ),
    )
    parser.add_argument(
        "--format",
        "-F",
        choices=("text", "json", "csv"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="PATH",
        help=(
            "write the report to PATH; use '-' for standard output. JSON/CSV "
            "default to a timestamped file in reports/"
        ),
    )
    parser.add_argument(
        "--threshold",
        type=_positive_int,
        default=DEFAULT_THRESHOLD,
        metavar="N",
        help=(
            "failed attempts from one IP within the window that trigger a "
            f"repeated-failure alert (default: {DEFAULT_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--high-threshold",
        type=_positive_int,
        default=DEFAULT_HIGH_THRESHOLD,
        metavar="N",
        help=(
            "failed attempts that escalate to a high-volume alert "
            f"(default: {DEFAULT_HIGH_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--window",
        type=_positive_float,
        default=DEFAULT_WINDOW_MINUTES,
        metavar="MINUTES",
        help=(
            "correlation window in minutes for repeated failures and "
            f"failure-then-success (default: {DEFAULT_WINDOW_MINUTES:g})"
        ),
    )
    parser.add_argument(
        "--year",
        type=_year,
        default=None,
        metavar="YYYY",
        help=(
            "year to use for syslog timestamps, which normally omit it "
            "(default: current UTC year)"
        ),
    )
    parser.add_argument(
        "--assume-tz",
        default=DEFAULT_TIMEZONE,
        metavar="TZ",
        help=(
            "IANA timezone for timestamps that carry no UTC offset, such as "
            f"syslog entries (default: {DEFAULT_TIMEZONE})"
        ),
    )
    parser.add_argument(
        "--no-single-failures",
        action="store_true",
        help=(
            "do not emit Low alerts for isolated single failures (useful for "
            "high-volume logs)"
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors in terminal output",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the notice printed after writing a report file",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _should_use_color(no_color: bool, output: Optional[str]) -> bool:
    if no_color or os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    if output and output != "-":
        return False
    return sys.stdout.isatty()


def _default_report_path(fmt: str, analyzed_at: datetime) -> Path:
    stamp = analyzed_at.strftime("%Y%m%dT%H%M%SZ")
    return Path("reports") / f"soc_report_{stamp}.{fmt}"


def _write_text_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(content)


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.high_threshold < args.threshold:
        parser.error("--high-threshold must be greater than or equal to --threshold")

    window_seconds = int(round(args.window * 60))
    if window_seconds < 1:
        parser.error("--window must be at least 0.017 minutes (one second)")

    input_path = Path(args.file).expanduser()
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1
    if not input_path.is_file():
        print(f"Error: input path is not a regular file: {input_path}", file=sys.stderr)
        return 1

    started = time.perf_counter()
    try:
        # Read once so the SHA-256 in the report describes exactly the bytes
        # that were analyzed, even if the source file changes mid-run.
        input_bytes = input_path.read_bytes()
    except OSError as exc:
        print(f"Error: cannot read input file: {exc}", file=sys.stderr)
        return 1
    input_sha256 = hashlib.sha256(input_bytes).hexdigest()

    try:
        log_parser = LogParser(year=args.year, assume_tz=args.assume_tz)
        parse_result = log_parser.parse_lines(
            input_bytes.decode("utf-8", errors="replace").splitlines(),
            source=str(input_path),
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    config = DetectionConfig(
        failure_threshold=args.threshold,
        high_volume_threshold=args.high_threshold,
        window_seconds=window_seconds,
        include_single_failures=not args.no_single_failures,
    )
    detector = Detector(config)
    detection = detector.detect(parse_result.events)

    analyzed_at = datetime.now(timezone.utc)
    duration_ms = int((time.perf_counter() - started) * 1000)
    report = build_report(
        parse_result=parse_result,
        detection=detection,
        input_path=str(input_path),
        analyzed_at=analyzed_at,
        duration_ms=duration_ms,
        input_sha256=input_sha256,
        detection_parameters={
            "failure_threshold": config.failure_threshold,
            "high_volume_threshold": config.high_volume_threshold,
            "window_seconds": config.window_seconds,
            "window_minutes": round(config.window_seconds / 60, 3),
            "single_failure_alerts": config.include_single_failures,
        },
    )

    fmt = args.format
    try:
        if fmt == "text":
            text = render_text(
                report,
                color=_should_use_color(args.no_color, args.output),
            )
            if args.output and args.output != "-":
                destination = Path(args.output).expanduser()
                _write_text_file(destination, text)
                if not args.quiet:
                    print(f"Text report written to {destination}")
            else:
                sys.stdout.write(text)
            return 0

        destination = args.output
        if destination is None:
            destination_path = _default_report_path(fmt, analyzed_at)
            destination = str(destination_path)
        if destination == "-":
            if fmt == "json":
                write_json(report, sys.stdout)
            else:
                write_csv(report, sys.stdout)
            return 0

        destination_path = Path(destination).expanduser()
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        with destination_path.open("w", encoding="utf-8", newline="") as handle:
            if fmt == "json":
                write_json(report, handle)
            else:
                write_csv(report, handle)
        if not args.quiet:
            print(f"{fmt.upper()} report written to {destination_path}")
        return 0
    except BrokenPipeError:
        return 0
    except OSError as exc:
        print(f"Error: cannot write report: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
