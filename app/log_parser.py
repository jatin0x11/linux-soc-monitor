"""Parse Linux authentication logs into normalized, evidence-preserving events.

Supported text inputs
---------------------
* Syslog / ``auth.log`` style records (RFC 3164-like)::

      Jan 15 09:00:01 web01 sshd[9001]: Failed password for root from 203.0.113.45 port 40002 ssh2

* Exported ``journalctl`` text using ISO-8601 timestamps (``short-iso``,
  ``short-iso-precise`` and similar)::

      2024-01-15T09:00:01+0000 web01 sshd[9001]: Failed password for root from 203.0.113.45 port 40002 ssh2

The parser is deliberately tolerant.  Lines it cannot understand are counted
and skipped instead of raising, and every recognised line keeps its original
text so an analyst can validate each finding.  Parsed events are normalised to
UTC, but ``timestamp_raw`` always retains the value found in the log.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional
from zoneinfo import ZoneInfo


# Event taxonomy -----------------------------------------------------------
EVENT_FAILED_LOGIN = "failed_login"
EVENT_SUCCESSFUL_LOGIN = "successful_login"
EVENT_INVALID_USER = "invalid_user"
EVENT_CONNECTION_CLOSED = "connection_closed"
EVENT_DISCONNECTED = "disconnected"
EVENT_CONNECTION = "connection"
EVENT_OTHER = "other"

AUTH_EVENT_TYPES = frozenset(
    {
        EVENT_FAILED_LOGIN,
        EVENT_SUCCESSFUL_LOGIN,
        EVENT_INVALID_USER,
        EVENT_CONNECTION_CLOSED,
        EVENT_DISCONNECTED,
        EVENT_CONNECTION,
    }
)

#: Lines that are structurally valid but carry no authentication meaning.
NON_AUTH_EVENT_TYPES = frozenset({EVENT_OTHER})


# Timestamp / record patterns ---------------------------------------------
_ISO_TIMESTAMP_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)"
)
_SYSLOG_TIMESTAMP_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
_SYSLOG_PARTS_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})$"
)
_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}
# hostname process[pid]: message   (process and pid are optional in a few
# unusual exports, but the common formats always contain both.)
_HEADER_RE = re.compile(
    r"^(?P<host>\S+)\s+"
    r"(?P<process>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# sshd message patterns ----------------------------------------------------
_FAILED_RE = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|"
    r"gssapi-with-mic|none) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+)"
    r"(?: port (?P<port>\d+))?"
)
_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|"
    r"gssapi-with-mic) for (?P<user>\S+) from (?P<ip>\S+)"
    r"(?: port (?P<port>\d+))?"
)
_INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)"
    r"(?: port (?P<port>\d+))?"
)
_MAX_AUTH_RE = re.compile(
    r"^error: maximum authentication attempts exceeded for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
    r"(?: port (?P<port>\d+))?"
)
_PAM_ERROR_RE = re.compile(
    r"^error: PAM: Authentication failure for "
    r"(?P<invalid>illegal user )?(?P<user>\S+) from (?P<ip>\S+)"
)
_PAM_UNKNOWN_USER_RE = re.compile(
    r"^error: PAM: User not known to the underlying authentication module for "
    r"illegal user (?P<user>\S+) from (?P<ip>\S+)"
)

_PAM_FAILURE_PREFIX = "pam_unix(sshd:auth): authentication failure"

# Connection lifecycle messages -------------------------------------------
_CONNECTION_CLOSED_USER_RE = re.compile(
    r"^Connection closed by (?:authenticating user|invalid user) "
    r"(?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"
)
_CONNECTION_CLOSED_IP_RE = re.compile(
    r"^Connection closed by (?P<ip>\S+) port (?P<port>\d+)"
)
_DISCONNECTED_RE = re.compile(
    r"^Disconnected from (?:invalid user |authenticating user |user )?"
    r"(?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"
)
_RECEIVED_DISCONNECT_RE = re.compile(
    r"^Received disconnect from (?P<ip>\S+) port (?P<port>\d+)"
)
_CONNECTION_RE = re.compile(
    r"^Connection from (?P<ip>\S+) port (?P<port>\d+)"
)
_NO_IDENT_RE = re.compile(
    r"^(?:Did not receive identification string|banner exchange: Connection) "
    r"from (?P<ip>\S+)"
)


@dataclass(frozen=True)
class Event:
    """A normalized authentication event.

    ``raw`` is the complete original log line.  It is retained as evidence and
    is never rewritten by the analyzer.
    """

    timestamp: Optional[datetime]
    timestamp_raw: str
    event_type: str
    username: Optional[str]
    source_ip: Optional[str]
    port: Optional[int]
    auth_method: Optional[str]
    invalid_user: bool
    hostname: Optional[str]
    process: Optional[str]
    pid: Optional[int]
    component: str
    message: str
    raw: str
    line_number: int

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation for reports."""
        return {
            "line_number": self.line_number,
            "timestamp": format_timestamp(self.timestamp),
            "timestamp_raw": self.timestamp_raw,
            "event_type": self.event_type,
            "username": self.username,
            "source_ip": self.source_ip,
            "port": self.port,
            "auth_method": self.auth_method,
            "invalid_user": self.invalid_user,
            "hostname": self.hostname,
            "process": self.process,
            "pid": self.pid,
            "component": self.component,
            "message": self.message,
            "raw": self.raw,
        }


@dataclass
class ParseResult:
    """Normalized events plus parser diagnostics."""

    events: list[Event]
    stats: dict
    unsupported_samples: list[dict]
    source: str
    assumed_timezone: str

    @property
    def auth_events(self) -> list[Event]:
        return [e for e in self.events if e.event_type in AUTH_EVENT_TYPES]

    @property
    def unparsed_lines(self) -> int:
        return int(self.stats.get("unparsed_lines", 0))


def format_timestamp(value: Optional[datetime]) -> Optional[str]:
    """Format an aware datetime as a compact UTC ISO-8601 string."""
    if value is None:
        return None
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _valid_ip(raw: Optional[str]) -> Optional[str]:
    """Validate and canonicalize an IP address; return ``None`` if invalid."""
    if not raw:
        return None
    candidate = raw.strip().strip("[]")
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _field(message: str, name: str) -> Optional[str]:
    """Extract a ``key=value`` field from a PAM-style message."""
    match = re.search(rf"\b{re.escape(name)}=(\S*)", message)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


def _port(raw: Optional[str]) -> Optional[int]:
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if 0 <= value <= 65535 else None


def _message_info(**overrides) -> dict:
    info = {
        "username": None,
        "source_ip_raw": None,
        "port": None,
        "auth_method": None,
        "invalid_user": False,
        "component": "sshd",
    }
    info.update(overrides)
    return info


def classify_message(message: str) -> tuple[str, dict]:
    """Classify an sshd message and extract available fields.

    Returns ``(event_type, fields)``.  Unrecognised messages become
    ``EVENT_OTHER`` so they are counted without affecting detections.
    """
    # pam_unix emits a second line for the same failed attempt.  It is parsed
    # and later deduplicated against the sshd failure when both are present.
    if message.startswith(_PAM_FAILURE_PREFIX):
        ip_raw = _field(message, "rhost")
        username = _field(message, "user")
        if username:
            return EVENT_FAILED_LOGIN, _message_info(
                username=username,
                source_ip_raw=ip_raw,
                component="pam",
            )
        return EVENT_OTHER, _message_info(component="pam")

    match = _PAM_ERROR_RE.match(message)
    if match:
        return EVENT_FAILED_LOGIN, _message_info(
            username=match.group("user"),
            source_ip_raw=match.group("ip"),
            invalid_user=bool(match.group("invalid")),
            component="pam",
        )

    match = _PAM_UNKNOWN_USER_RE.match(message)
    if match:
        return EVENT_INVALID_USER, _message_info(
            username=match.group("user"),
            source_ip_raw=match.group("ip"),
            invalid_user=True,
            component="pam",
        )

    match = _ACCEPTED_RE.match(message)
    if match:
        return EVENT_SUCCESSFUL_LOGIN, _message_info(
            username=match.group("user"),
            source_ip_raw=match.group("ip"),
            port=_port(match.group("port")),
            auth_method=match.group("method"),
        )

    match = _FAILED_RE.match(message)
    if match:
        return EVENT_FAILED_LOGIN, _message_info(
            username=match.group("user"),
            source_ip_raw=match.group("ip"),
            port=_port(match.group("port")),
            auth_method=match.group("method"),
            invalid_user=bool(match.group("invalid")),
        )

    match = _INVALID_USER_RE.match(message)
    if match:
        return EVENT_INVALID_USER, _message_info(
            username=match.group("user"),
            source_ip_raw=match.group("ip"),
            port=_port(match.group("port")),
            invalid_user=True,
        )

    match = _MAX_AUTH_RE.match(message)
    if match:
        return EVENT_FAILED_LOGIN, _message_info(
            username=match.group("user"),
            source_ip_raw=match.group("ip"),
            port=_port(match.group("port")),
            invalid_user=bool(match.group("invalid")),
        )

    match = _CONNECTION_CLOSED_USER_RE.match(message)
    if match:
        return EVENT_CONNECTION_CLOSED, _message_info(
            username=match.group("user"),
            source_ip_raw=match.group("ip"),
            port=_port(match.group("port")),
            invalid_user="invalid user" in message,
        )

    match = _CONNECTION_CLOSED_IP_RE.match(message)
    if match:
        return EVENT_CONNECTION_CLOSED, _message_info(
            source_ip_raw=match.group("ip"),
            port=_port(match.group("port")),
        )

    match = _DISCONNECTED_RE.match(message)
    if match:
        return EVENT_DISCONNECTED, _message_info(
            username=match.group("user"),
            source_ip_raw=match.group("ip"),
            port=_port(match.group("port")),
            invalid_user="invalid user" in message,
        )

    match = _RECEIVED_DISCONNECT_RE.match(message)
    if match:
        return EVENT_DISCONNECTED, _message_info(
            source_ip_raw=match.group("ip"),
            port=_port(match.group("port")),
        )

    match = _CONNECTION_RE.match(message)
    if match:
        return EVENT_CONNECTION, _message_info(
            source_ip_raw=match.group("ip"),
            port=_port(match.group("port")),
        )

    match = _NO_IDENT_RE.match(message)
    if match:
        return EVENT_CONNECTION, _message_info(
            source_ip_raw=match.group("ip"),
        )

    return EVENT_OTHER, _message_info()


class LogParser:
    """Stateful parser for one log file.

    Syslog timestamps have no year and no timezone.  ``year`` overrides the
    inferred year (default: current UTC year) and ``assume_tz`` supplies the
    timezone for timestamp values that carry no offset.  A simple year
    rollover is applied when a syslog timestamp jumps backwards by more than
    180 days (for example, a log spanning 31 December to 1 January).
    """

    MAX_UNSUPPORTED_SAMPLES = 10

    def __init__(self, year: Optional[int] = None, assume_tz: str = "UTC") -> None:
        try:
            self._timezone = ZoneInfo(assume_tz)
        except Exception as exc:  # ZoneInfoNotFoundError and platform issues
            raise ValueError(
                f"unknown timezone {assume_tz!r}; use an IANA name such as UTC "
                "or Europe/London"
            ) from exc
        self._year_override = year
        self._active_year = year or datetime.now(timezone.utc).year
        self._last_syslog_naive: Optional[datetime] = None

    # -- public API --------------------------------------------------------
    def parse_file(self, path: str | Path) -> ParseResult:
        path = Path(path)
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return self.parse_lines(handle, source=str(path))

    def parse_lines(
        self, lines: Iterable[str], source: str = "<stream>"
    ) -> ParseResult:
        self._active_year = self._year_override or datetime.now(timezone.utc).year
        self._last_syslog_naive = None

        events: list[Event] = []
        stats = {
            "lines_read": 0,
            "blank_lines": 0,
            "events_parsed": 0,
            "non_auth_events": 0,
            "unparsed_lines": 0,
            "unparsed_reasons": {},
            "pam_duplicates_removed": 0,
        }
        unsupported_samples: list[dict] = []

        for line_number, line in enumerate(lines, start=1):
            stats["lines_read"] += 1
            raw = line.rstrip("\r\n")
            if not raw.strip():
                stats["blank_lines"] += 1
                continue

            event, reason = self._parse_line(raw, line_number)
            if event is None:
                stats["unparsed_lines"] += 1
                reason = reason or "unknown"
                stats["unparsed_reasons"][reason] = (
                    stats["unparsed_reasons"].get(reason, 0) + 1
                )
                if len(unsupported_samples) < self.MAX_UNSUPPORTED_SAMPLES:
                    unsupported_samples.append(
                        {
                            "line_number": line_number,
                            "reason": reason,
                            "raw": raw[:500],
                        }
                    )
                continue

            events.append(event)

        events, duplicates = self._deduplicate_pam_failures(events)
        stats["pam_duplicates_removed"] = duplicates
        stats["events_parsed"] = len(events)
        stats["non_auth_events"] = sum(
            1 for event in events if event.event_type == EVENT_OTHER
        )
        return ParseResult(
            events=events,
            stats=stats,
            unsupported_samples=unsupported_samples,
            source=source,
            assumed_timezone=str(self._timezone),
        )

    # -- parsing internals -------------------------------------------------
    def _parse_line(
        self, line: str, line_number: int
    ) -> tuple[Optional[Event], Optional[str]]:
        match = _ISO_TIMESTAMP_RE.match(line)
        if match:
            timestamp_raw = match.group("ts")
            remainder = line[match.end() :].lstrip()
        else:
            match = _SYSLOG_TIMESTAMP_RE.match(line)
            if not match:
                return None, "missing_timestamp"
            timestamp_raw = match.group("ts")
            remainder = line[match.end() :].lstrip()

        try:
            timestamp = self._parse_timestamp(timestamp_raw)
        except (ValueError, OverflowError):
            return None, "malformed_timestamp"

        header = _HEADER_RE.match(remainder)
        if not header:
            return None, "unrecognized_structure"

        message = header.group("message")
        event_type, info = classify_message(message)
        source_ip = _valid_ip(info["source_ip_raw"])

        return (
            Event(
                timestamp=timestamp,
                timestamp_raw=timestamp_raw,
                event_type=event_type,
                username=info["username"],
                source_ip=source_ip,
                port=info["port"],
                auth_method=info["auth_method"],
                invalid_user=bool(info["invalid_user"]),
                hostname=header.group("host"),
                process=header.group("process"),
                pid=int(header.group("pid")) if header.group("pid") else None,
                component=info["component"],
                message=message,
                raw=line,
                line_number=line_number,
            ),
            None,
        )

    def _parse_timestamp(self, raw: str) -> datetime:
        if raw[:4].isdigit():
            normalized = raw.replace(" ", "T", 1)
            normalized = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", normalized)
            if normalized.endswith(("Z", "z")):
                normalized = normalized[:-1] + "+00:00"
            # Python 3.9's fromisoformat requires 3 or 6 fractional digits.
            # Normalize any precision to exactly six digits.
            normalized = re.sub(
                r"\.(\d{1,9})(?=[+-]|$)",
                lambda match: "." + (match.group(1) + "000000")[:6],
                normalized,
            )
            value = datetime.fromisoformat(normalized)
            if value.tzinfo is None:
                value = value.replace(tzinfo=self._timezone)
            return value.astimezone(timezone.utc)

        compact = re.sub(r"\s+", " ", raw.strip())
        parts = _SYSLOG_PARTS_RE.match(compact)
        if parts is None:
            raise ValueError(f"unrecognized syslog timestamp: {raw!r}")
        month = _MONTHS.get(parts.group("month"))
        if month is None:
            raise ValueError(f"unknown month in syslog timestamp: {raw!r}")
        # Parse the timestamp explicitly instead of using strptime so the
        # analyzer is not affected by the system locale.
        naive = datetime(
            self._active_year,
            month,
            int(parts.group("day")),
            int(parts.group("hour")),
            int(parts.group("minute")),
            int(parts.group("second")),
        )

        # Handle an inferred New Year rollover.  This cannot disambiguate
        # genuinely out-of-order logs, which is documented as a limitation.
        if (
            self._last_syslog_naive is not None
            and naive < self._last_syslog_naive - timedelta(days=180)
        ):
            self._active_year += 1
            naive = naive.replace(year=self._active_year)

        self._last_syslog_naive = naive
        return naive.replace(tzinfo=self._timezone).astimezone(timezone.utc)

    @staticmethod
    def _deduplicate_pam_failures(
        events: list[Event],
    ) -> tuple[list[Event], int]:
        """Drop pam_unix failure lines that duplicate an sshd failure line.

        Both processes usually log the same failed attempt in the same second.
        Keeping both would double-count failures and inflate thresholds.
        """
        sshd_keys = {
            (
                event.source_ip,
                event.username,
                event.timestamp.replace(microsecond=0),
            )
            for event in events
            if event.event_type == EVENT_FAILED_LOGIN
            and event.component == "sshd"
            and event.source_ip
            and event.timestamp
        }

        kept: list[Event] = []
        removed = 0
        for event in events:
            if (
                event.event_type == EVENT_FAILED_LOGIN
                and event.component == "pam"
                and event.source_ip
                and event.timestamp
                and (
                    event.source_ip,
                    event.username,
                    event.timestamp.replace(microsecond=0),
                )
                in sshd_keys
            ):
                removed += 1
                continue
            kept.append(event)
        return kept, removed
