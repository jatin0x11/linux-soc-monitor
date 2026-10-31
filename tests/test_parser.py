"""Parser behavior: normalization, tolerance, and evidence retention."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.log_parser import (
    EVENT_CONNECTION,
    EVENT_CONNECTION_CLOSED,
    EVENT_DISCONNECTED,
    EVENT_FAILED_LOGIN,
    EVENT_INVALID_USER,
    EVENT_OTHER,
    EVENT_SUCCESSFUL_LOGIN,
    LogParser,
)


def parse(lines, **kwargs):
    return LogParser(year=kwargs.pop("year", 2024), **kwargs).parse_lines(lines)


def test_parses_failed_password_with_port():
    raw = (
        "Jan 15 09:00:01 web01 sshd[9001]: Failed password for root "
        "from 203.0.113.45 port 40003 ssh2"
    )
    result = parse([raw])

    assert len(result.events) == 1
    event = result.events[0]
    assert event.event_type == EVENT_FAILED_LOGIN
    assert event.username == "root"
    assert event.source_ip == "203.0.113.45"
    assert event.port == 40003
    assert event.auth_method == "password"
    assert event.invalid_user is False
    assert event.hostname == "web01"
    assert event.process == "sshd"
    assert event.pid == 9001
    assert event.line_number == 1
    assert event.raw == raw
    assert event.timestamp == datetime(2024, 1, 15, 9, 0, 1, tzinfo=timezone.utc)
    assert event.timestamp_raw == "Jan 15 09:00:01"


def test_parses_failed_password_for_invalid_user():
    result = parse(
        [
            "Jan 15 09:00:01 web01 sshd[9001]: Failed password for invalid user "
            "admin from 203.0.113.45 port 40001 ssh2"
        ]
    )
    event = result.events[0]
    assert event.event_type == EVENT_FAILED_LOGIN
    assert event.username == "admin"
    assert event.invalid_user is True


def test_parses_successful_publickey_login():
    result = parse(
        [
            "Jan 15 08:01:12 web01 sshd[2101]: Accepted publickey for deploy "
            "from 192.0.2.10 port 51222 ssh2: ED25519 SHA256:AAAA"
        ]
    )
    event = result.events[0]
    assert event.event_type == EVENT_SUCCESSFUL_LOGIN
    assert event.auth_method == "publickey"
    assert event.username == "deploy"
    assert event.source_ip == "192.0.2.10"
    assert event.port == 51222


def test_parses_invalid_user_announcement():
    result = parse(
        [
            "Jan 15 09:35:00 web01 sshd[9301]: Invalid user test "
            "from 192.0.2.66 port 44001"
        ]
    )
    event = result.events[0]
    assert event.event_type == EVENT_INVALID_USER
    assert event.username == "test"
    assert event.invalid_user is True
    assert event.port == 44001


def test_parses_iso_timestamp_with_offset_and_converts_to_utc():
    result = parse(
        [
            "2024-02-02T11:00:01-0500 db01 sshd[5001]: Failed password for root "
            "from 203.0.113.99 port 60001 ssh2"
        ]
    )
    event = result.events[0]
    assert event.timestamp == datetime(2024, 2, 2, 16, 0, 1, tzinfo=timezone.utc)
    assert event.timestamp_raw == "2024-02-02T11:00:01-0500"


def test_iso_timestamp_with_fractional_seconds():
    result = parse(
        [
            "2024-02-02T11:10:00.123456+00:00 db01 sshd[5010]: "
            "Invalid user admin from 198.51.100.23 port 60010"
        ]
    )
    assert result.events[0].timestamp == datetime(
        2024, 2, 2, 11, 10, 0, 123456, tzinfo=timezone.utc
    )


def test_iso_timestamp_with_short_fractional_seconds():
    result = parse(
        [
            "2024-02-02T11:10:00.1Z db01 sshd[5010]: "
            "Invalid user admin from 198.51.100.23 port 60010"
        ]
    )
    assert result.events[0].timestamp == datetime(
        2024, 2, 2, 11, 10, 0, 100000, tzinfo=timezone.utc
    )


def test_offset_less_iso_timestamp_uses_assumed_timezone():
    result = parse(
        [
            "2024-02-02T11:00:01 db01 sshd[5001]: Failed password for root "
            "from 203.0.113.99 port 60001 ssh2"
        ],
        assume_tz="America/New_York",
    )
    assert result.events[0].timestamp == datetime(
        2024, 2, 2, 16, 0, 1, tzinfo=timezone.utc
    )


def test_syslog_timestamps_use_current_year_by_default():
    result = LogParser().parse_lines(
        [
            "Jan 15 09:00:01 web01 sshd[1]: Failed password for root "
            "from 203.0.113.45 port 22 ssh2"
        ]
    )
    current_year = datetime.now(timezone.utc).year
    assert result.events[0].timestamp.year == current_year


def test_syslog_year_rollover_is_inferred():
    result = parse(
        [
            "Dec 31 23:59:59 web01 sshd[1]: Failed password for root "
            "from 203.0.113.45 port 22 ssh2",
            "Jan  1 00:00:01 web01 sshd[2]: Failed password for root "
            "from 203.0.113.45 port 23 ssh2",
        ]
    )
    assert result.events[0].timestamp == datetime(
        2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc
    )
    assert result.events[1].timestamp == datetime(
        2025, 1, 1, 0, 0, 1, tzinfo=timezone.utc
    )


def test_invalid_ip_is_not_used_for_correlation():
    result = parse(
        [
            "Jan 15 09:42:00 web01 sshd[9500]: Failed password for root "
            "from not-an-ip port 22 ssh2"
        ]
    )
    event = result.events[0]
    assert event.event_type == EVENT_FAILED_LOGIN
    assert event.source_ip is None
    assert event.username == "root"


def test_ipv6_address_is_canonicalized():
    result = parse(
        [
            "Jan 15 09:43:00 web01 sshd[9501]: Connection from "
            "2001:0db8:0:0:0:0:0:7 port 22"
        ]
    )
    assert result.events[0].source_ip == "2001:db8::7"


def test_pam_failure_duplicate_is_removed():
    result = parse(
        [
            "Jan 15 09:50:00 web01 sshd[9401]: Failed password for bob "
            "from 192.0.2.77 port 52000 ssh2",
            "Jan 15 09:50:00 web01 sshd[9401]: pam_unix(sshd:auth): "
            "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
            "rhost=192.0.2.77 user=bob",
        ]
    )
    assert len(result.events) == 1
    assert result.events[0].component == "sshd"
    assert result.stats["pam_duplicates_removed"] == 1
    assert result.stats["lines_read"] == 2


def test_pam_failure_is_kept_without_matching_sshd_line():
    result = parse(
        [
            "Jan 15 09:50:02 web01 sshd[9402]: pam_unix(sshd:auth): "
            "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
            "rhost=192.0.2.77 user=carol"
        ]
    )
    event = result.events[0]
    assert event.event_type == EVENT_FAILED_LOGIN
    assert event.component == "pam"
    assert event.username == "carol"
    assert event.source_ip == "192.0.2.77"


def test_pam_error_for_illegal_user_is_flagged_invalid():
    result = parse(
        [
            "Jan 15 09:45:00 web01 sshd[9503]: error: PAM: Authentication "
            "failure for illegal user admin from 198.51.100.88"
        ]
    )
    event = result.events[0]
    assert event.event_type == EVENT_FAILED_LOGIN
    assert event.invalid_user is True
    assert event.username == "admin"


def test_maximum_authentication_attempts_is_a_failure():
    result = parse(
        [
            "Jan 15 09:20:00 web01 sshd[9210]: error: maximum authentication "
            "attempts exceeded for invalid user git from 192.0.2.90 port 45001 "
            "ssh2 [preauth]"
        ]
    )
    event = result.events[0]
    assert event.event_type == EVENT_FAILED_LOGIN
    assert event.invalid_user is True
    assert event.username == "git"
    assert event.port == 45001


def test_header_without_pid_is_supported():
    result = parse(
        [
            "Jan 15 09:00:01 web01 sshd: Failed password for root "
            "from 203.0.113.45 port 22 ssh2"
        ]
    )
    assert result.events[0].process == "sshd"
    assert result.events[0].pid is None


def test_connection_lifecycle_events_are_classified():
    result = parse(
        [
            "Jan 15 09:12:35 web01 sshd[1]: Received disconnect from "
            "198.51.100.77 port 41011:11: Bye Bye [preauth]",
            "Jan 15 09:35:01 web01 sshd[2]: Connection closed by invalid user "
            "test 192.0.2.66 port 44001 [preauth]",
            "Jan 15 09:43:00 web01 sshd[3]: Connection from 2001:db8::7 port 22",
            "Jan 15 09:35:01 web01 sshd[4]: Disconnected from user alice "
            "192.0.2.66 port 44002",
        ]
    )
    assert [event.event_type for event in result.events] == [
        EVENT_DISCONNECTED,
        EVENT_CONNECTION_CLOSED,
        EVENT_CONNECTION,
        EVENT_DISCONNECTED,
    ]
    assert result.events[1].invalid_user is True


def test_malformed_and_unrelated_lines_do_not_crash():
    result = parse(
        [
            "Jan 15 09:40:00 web01 sshd[9999] Failed password for root "
            "from 203.0.113.9 port 1234 ssh2",
            "this is not a log line",
            "",
            "Jan 15 09:00:01",
            "Feb 30 09:00:01 web01 sshd[1]: Failed password for root "
            "from 203.0.113.45 port 22 ssh2",
        ]
    )
    assert result.events == []
    assert result.stats["lines_read"] == 5
    assert result.stats["blank_lines"] == 1
    assert result.stats["unparsed_lines"] == 4
    assert result.stats["unparsed_reasons"]["missing_timestamp"] == 1
    assert result.stats["unparsed_reasons"]["unrecognized_structure"] == 2
    assert result.stats["unparsed_reasons"]["malformed_timestamp"] == 1
    assert 1 <= len(result.unsupported_samples) <= 10


def test_unrelated_system_messages_are_other_events():
    result = parse(
        [
            "Jan 15 10:00:00 web01 sudo: alice : TTY=pts/0 ; "
            "PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
        ]
    )
    assert len(result.events) == 1
    assert result.events[0].event_type == EVENT_OTHER
    assert result.stats["non_auth_events"] == 1
    assert result.auth_events == []


def test_parse_file_reads_and_counts(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Jan 15 09:00:01 web01 sshd[1]: Failed password for root "
        "from 203.0.113.45 port 22 ssh2\n"
        "not a log line\n",
        encoding="utf-8",
    )
    fresh = LogParser(year=2024).parse_file(log)
    assert fresh.source == str(log)
    assert len(fresh.events) == 1
    assert fresh.stats["lines_read"] == 2
    assert fresh.stats["unparsed_lines"] == 1


def test_unknown_timezone_is_rejected():
    with pytest.raises(ValueError, match="unknown timezone"):
        LogParser(assume_tz="Not/AZone")
