"""Factory helpers so tests can build normalized events concisely."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.log_parser import EVENT_FAILED_LOGIN, Event

BASE_TIME = datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
_UNSET = object()


def make_event(
    offset: float = 0,
    *,
    event_type: str = EVENT_FAILED_LOGIN,
    source_ip: str | None = "203.0.113.5",
    username: str | None = "root",
    port: int | None = None,
    invalid_user: bool = False,
    line_number: int | None = None,
    timestamp=_UNSET,
    raw: str | None = None,
) -> Event:
    """Create an event at ``BASE_TIME + offset seconds``."""
    if timestamp is _UNSET:
        timestamp = BASE_TIME + timedelta(seconds=offset)
    if line_number is None:
        line_number = int(offset) + 1
    if raw is None:
        raw = (
            f"Jan 15 09:00:{int(offset) % 60:02d} testhost sshd[100]: "
            f"{event_type} user={username} from {source_ip}"
        )
    return Event(
        timestamp=timestamp,
        timestamp_raw=(
            timestamp.isoformat() if isinstance(timestamp, datetime) else "invalid"
        ),
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        port=port,
        auth_method="password" if event_type == EVENT_FAILED_LOGIN else None,
        invalid_user=invalid_user,
        hostname="testhost",
        process="sshd",
        pid=100,
        component="sshd",
        message=raw,
        raw=raw,
        line_number=line_number,
    )
