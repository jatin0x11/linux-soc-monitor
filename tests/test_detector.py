"""Detection behavior, threshold boundaries, and correlation isolation."""

from __future__ import annotations

import pytest

from app.detector import (
    Detector,
    DetectionConfig,
    RULES,
    SEVERITY_ORDER,
    group_invalid_user_attempts,
)
from app.log_parser import (
    EVENT_FAILED_LOGIN,
    EVENT_INVALID_USER,
    EVENT_SUCCESSFUL_LOGIN,
)
from tests.event_factory import make_event


def run(events, **config):
    return Detector(DetectionConfig(**config)).detect(events)


def failures(count, source_ip="203.0.113.5", spacing=30, start=0, **kwargs):
    return [
        make_event(
            offset=start + index * spacing,
            source_ip=source_ip,
            line_number=index + 1,
            **kwargs,
        )
        for index in range(count)
    ]


def rules(result):
    return [alert.rule_id for alert in result.alerts]


def test_single_failure_generates_low_alert():
    result = run([make_event()])
    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert alert.rule_id == "R001"
    assert alert.severity == "Low"
    assert alert.source_ip == "203.0.113.5"
    assert alert.failure_count == 1
    assert alert.evidence[0].event_type == EVENT_FAILED_LOGIN


def test_four_failures_stay_below_default_threshold():
    result = run(failures(4, spacing=60))
    assert "R002" not in rules(result)
    assert rules(result) == ["R001"] * 4
    assert all(alert.severity == "Low" for alert in result.alerts)


def test_five_failures_within_window_generate_one_medium_alert():
    result = run(failures(5, spacing=60))
    assert rules(result) == ["R002"]
    alert = result.alerts[0]
    assert alert.severity == "Medium"
    assert alert.failure_count == 5
    assert len(alert.evidence) == 5
    assert alert.mitre_attack[0]["technique_id"] == "T1110.001"


def test_ten_failures_generate_high_volume_alert_only():
    result = run(failures(10, spacing=30))
    assert rules(result) == ["R003"]
    alert = result.alerts[0]
    assert alert.severity == "High"
    assert alert.failure_count == 10


def test_window_boundary_is_inclusive():
    events = failures(4, spacing=60) + [
        make_event(offset=300, line_number=50)
    ]
    result = run(events)
    assert rules(result) == ["R002"]


def test_event_just_outside_window_does_not_count():
    events = failures(4, spacing=60) + [
        make_event(offset=301, line_number=50)
    ]
    result = run(events)
    assert "R002" not in rules(result)
    assert len(result.alerts) == 5


def test_different_source_ips_are_never_combined():
    events = failures(3, source_ip="203.0.113.5") + failures(
        3, source_ip="198.51.100.7", start=1
    )
    result = run(events)
    assert "R002" not in rules(result)
    assert "R003" not in rules(result)
    assert len(result.alerts) == 6


def test_separate_bursts_generate_separate_alerts():
    events = failures(5, spacing=60, start=0) + failures(
        5, spacing=60, start=1200
    )
    result = run(events)
    assert rules(result) == ["R002", "R002"]
    assert result.alerts[0].source_ip == "203.0.113.5"


def test_custom_threshold_and_window_are_applied():
    events = failures(3, spacing=10)
    result = run(events, failure_threshold=3, window_seconds=60)
    assert rules(result) == ["R002"]

    spread = failures(3, spacing=40)
    result = run(spread, failure_threshold=3, window_seconds=60)
    assert "R002" not in rules(result)
    assert len(result.alerts) == 3


def test_invalid_user_lines_for_one_attempt_are_grouped():
    events = [
        make_event(
            offset=0,
            event_type=EVENT_INVALID_USER,
            username="admin",
            port=40001,
            invalid_user=True,
            line_number=1,
        ),
        make_event(
            offset=1,
            event_type=EVENT_FAILED_LOGIN,
            username="admin",
            port=40001,
            invalid_user=True,
            line_number=2,
        ),
    ]
    groups = group_invalid_user_attempts(events)
    assert len(groups) == 1
    assert len(groups[0]) == 2

    result = run(events)
    assert rules(result) == ["R004"]
    alert = result.alerts[0]
    assert alert.severity == "Medium"
    assert alert.failure_count == 1
    assert len(alert.evidence) == 2
    assert result.invalid_user_attempts == 1


def test_invalid_user_same_port_reused_later_is_a_separate_attempt():
    events = [
        make_event(
            offset=0,
            event_type=EVENT_INVALID_USER,
            username="admin",
            port=40001,
            invalid_user=True,
            line_number=1,
        ),
        make_event(
            offset=600,
            event_type=EVENT_INVALID_USER,
            username="admin",
            port=40001,
            invalid_user=True,
            line_number=2,
        ),
    ]
    groups = group_invalid_user_attempts(events)
    assert len(groups) == 2
    assert len(run(events).alerts) == 2


def test_invalid_user_alert_without_source_ip_is_not_generated():
    result = run(
        [
            make_event(
                event_type=EVENT_INVALID_USER,
                source_ip=None,
                username="admin",
                invalid_user=True,
            )
        ]
    )
    assert result.alerts == []
    assert result.skipped_events_missing_fields == 1


def test_invalid_user_alert_without_timestamp_is_not_generated():
    result = run(
        [
            make_event(
                event_type=EVENT_INVALID_USER,
                username="admin",
                invalid_user=True,
                timestamp=None,
            )
        ]
    )
    assert result.alerts == []
    assert result.skipped_events_missing_fields == 1


def test_failed_login_without_timestamp_is_not_used_for_detection():
    result = run([make_event(timestamp=None)])
    assert result.alerts == []
    assert result.skipped_events_missing_fields == 1
    assert result.failures_analyzed == 1


def test_failure_then_success_is_high_with_evidence():
    events = failures(5, spacing=60) + [
        make_event(
            offset=300,
            event_type=EVENT_SUCCESSFUL_LOGIN,
            username="deploy",
            line_number=99,
        )
    ]
    result = run(events)
    assert "R005" in rules(result)
    assert "R002" in rules(result)
    sequence = next(a for a in result.alerts if a.rule_id == "R005")
    assert sequence.severity == "High"
    assert sequence.failure_count == 5
    assert sequence.evidence[-1].event_type == EVENT_SUCCESSFUL_LOGIN
    assert sequence.usernames == ["deploy", "root"]
    assert {item["technique_id"] for item in sequence.mitre_attack} == {
        "T1110.001",
        "T1078",
    }
    # High severities sort first and receive deterministic IDs.
    assert result.alerts[0].severity == "High"
    assert result.alerts[0].alert_id == "ALT-0001"


def test_success_without_repeated_failures_is_not_flagged():
    events = failures(4, spacing=60) + [
        make_event(
            offset=300,
            event_type=EVENT_SUCCESSFUL_LOGIN,
            username="deploy",
            line_number=99,
        )
    ]
    result = run(events)
    assert "R005" not in rules(result)


def test_success_from_different_ip_is_not_correlated():
    events = failures(6, spacing=30) + [
        make_event(
            offset=200,
            event_type=EVENT_SUCCESSFUL_LOGIN,
            source_ip="192.0.2.99",
            username="deploy",
            line_number=99,
        )
    ]
    result = run(events)
    assert "R005" not in rules(result)


def test_success_outside_window_is_not_correlated():
    events = failures(5, spacing=60) + [
        make_event(
            offset=301,
            event_type=EVENT_SUCCESSFUL_LOGIN,
            username="deploy",
            line_number=99,
        )
    ]
    result = run(events)
    assert "R005" not in rules(result)


def test_single_failure_alerts_can_be_disabled():
    result = run([make_event()], include_single_failures=False)
    assert result.alerts == []


def test_failures_covered_by_a_burst_do_not_get_low_alerts():
    result = run(failures(5, spacing=60))
    assert rules(result) == ["R002"]
    assert len(result.alerts[0].evidence) == 5
    assert all(alert.severity != "Low" for alert in result.alerts)


def test_alert_ids_and_ordering_are_deterministic():
    events = [
        make_event(offset=0, source_ip="198.51.100.7", line_number=1),
        make_event(offset=10, source_ip="203.0.113.5", line_number=2),
    ]
    first = run(events)
    second = run(list(reversed(events)))
    assert [a.alert_id for a in first.alerts] == ["ALT-0001", "ALT-0002"]
    assert [a.alert_id for a in first.alerts] == [
        a.alert_id for a in second.alerts
    ]
    assert [a.timestamp for a in first.alerts] == [
        a.timestamp for a in second.alerts
    ]


def test_source_summary_counts_and_sorts():
    events = failures(3, source_ip="203.0.113.5", spacing=60) + [
        make_event(
            offset=10,
            event_type=EVENT_SUCCESSFUL_LOGIN,
            source_ip="203.0.113.5",
            username="deploy",
            line_number=50,
        ),
        make_event(offset=15, source_ip="198.51.100.7", line_number=51),
    ]
    result = run(events)
    assert result.sources[0]["source_ip"] == "203.0.113.5"
    assert result.sources[0]["failed_logins"] == 3
    assert result.sources[0]["successful_logins"] == 1
    assert result.sources[0]["usernames"] == ["deploy", "root"]
    assert result.sources[1]["source_ip"] == "198.51.100.7"
    assert result.sources[1]["failed_logins"] == 1
    assert result.sources[0]["alerts"] >= 1


def test_empty_event_list_is_safe():
    result = run([])
    assert result.alerts == []
    assert result.sources == []
    assert result.invalid_user_attempts == 0
    assert result.alerts_by_severity() == {"High": 0, "Medium": 0, "Low": 0}


def test_configuration_validation():
    with pytest.raises(ValueError):
        DetectionConfig(failure_threshold=0)
    with pytest.raises(ValueError):
        DetectionConfig(failure_threshold=5, high_volume_threshold=4)
    with pytest.raises(ValueError):
        DetectionConfig(window_seconds=0)


def test_rule_metadata_is_consistent():
    for rule_id, rule in RULES.items():
        assert rule.rule_id == rule_id
        assert rule.severity in SEVERITY_ORDER
        assert rule.name
        assert rule.analyst_action
