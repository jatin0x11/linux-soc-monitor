"""Rule-based detection and triage for normalized authentication events.

Rules are heuristics, not proof of compromise.  Every alert carries the
supporting events so an analyst can validate the finding against the raw log.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Optional

from .log_parser import (
    AUTH_EVENT_TYPES,
    EVENT_FAILED_LOGIN,
    EVENT_INVALID_USER,
    EVENT_SUCCESSFUL_LOGIN,
    Event,
    format_timestamp,
)


SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
SEVERITIES = ("High", "Medium", "Low")

MITRE_TECHNIQUES = {
    "T1110.001": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1078": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: str
    analyst_action: str


RULES = {
    "R001": Rule(
        rule_id="R001",
        name="Single failed SSH login",
        severity="Low",
        analyst_action=(
            "Review context if needed; a single failure is commonly a mistyped "
            "password or stale credential."
        ),
    ),
    "R002": Rule(
        rule_id="R002",
        name="Repeated SSH authentication failures",
        severity="Medium",
        analyst_action=(
            "Validate the source, targeted accounts, and whether any login "
            "succeeded. Consider network-edge blocking after validation."
        ),
    ),
    "R003": Rule(
        rule_id="R003",
        name="High-volume SSH authentication failures",
        severity="High",
        analyst_action=(
            "Prioritise investigation: validate source reputation and target "
            "accounts, and search for any successful login from the same IP."
        ),
    ),
    "R004": Rule(
        rule_id="R004",
        name="Invalid username authentication attempt",
        severity="Medium",
        analyst_action=(
            "Confirm whether the username exists and whether several invalid "
            "names were tried; this may indicate account enumeration."
        ),
    ),
    "R005": Rule(
        rule_id="R005",
        name="Failure followed by successful login",
        severity="High",
        analyst_action=(
            "Treat the account as potentially compromised until validated. "
            "Confirm the login with the account owner, review session activity, "
            "and rotate credentials if suspicious."
        ),
    ),
}


@dataclass(frozen=True)
class DetectionConfig:
    """Configurable detection thresholds.

    Values are triage heuristics, not universal indicators of compromise.
    """

    failure_threshold: int = 5
    high_volume_threshold: int = 10
    window_seconds: int = 300
    include_single_failures: bool = True

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise ValueError("failure threshold must be at least 1")
        if self.high_volume_threshold < self.failure_threshold:
            raise ValueError(
                "high-volume threshold must be greater than or equal to the "
                "repeated-failure threshold"
            )
        if self.window_seconds < 1:
            raise ValueError("window must be at least one second")


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    timestamp: Optional[datetime]
    source_ip: Optional[str]
    usernames: list[str]
    failure_count: int
    window_start: Optional[datetime]
    window_end: Optional[datetime]
    reason: str
    analyst_action: str
    mitre_attack: list[dict]
    evidence: list[Event]

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "timestamp": format_timestamp(self.timestamp),
            "source_ip": self.source_ip,
            "usernames": self.usernames,
            "failure_count": self.failure_count,
            "window_start": format_timestamp(self.window_start),
            "window_end": format_timestamp(self.window_end),
            "reason": self.reason,
            "analyst_action": self.analyst_action,
            "mitre_attack": self.mitre_attack,
            "evidence_count": len(self.evidence),
            "evidence": [event.to_dict() for event in self.evidence],
        }


@dataclass
class DetectionResult:
    alerts: list[Alert]
    sources: list[dict]
    invalid_user_attempts: int
    skipped_events_missing_fields: int
    failures_analyzed: int
    successes_analyzed: int

    def alerts_by_severity(self) -> dict:
        counts = {severity: 0 for severity in SEVERITIES}
        for alert in self.alerts:
            counts[alert.severity] = counts.get(alert.severity, 0) + 1
        return counts


@dataclass
class _FailureCluster:
    start: int
    end: int
    candidates: list[tuple[int, int, int]]


def _event_sort_key(event: Event) -> tuple:
    if event.timestamp is None:
        return (True, datetime.min, event.line_number)
    return (False, event.timestamp, event.line_number)


def _usernames(events: list[Event]) -> list[str]:
    return sorted({event.username for event in events if event.username})


def _mitre(*technique_ids: str) -> list[dict]:
    return [dict(MITRE_TECHNIQUES[technique_id]) for technique_id in technique_ids]


def group_invalid_user_attempts(events: list[Event]) -> list[list[Event]]:
    """Group sshd's related invalid-user lines into single attempts.

    sshd commonly emits an ``Invalid user ...`` line and a matching
    ``Failed password for invalid user ...`` line for the same source port.
    Grouping by source port (or by time when no port is available) prevents a
    single attempt from being counted twice.
    """
    relevant = [
        event
        for event in events
        if event.invalid_user
        and event.username
        and event.event_type in (EVENT_FAILED_LOGIN, EVENT_INVALID_USER)
    ]
    relevant.sort(key=_event_sort_key)

    groups: dict[tuple, list[Event]] = {}
    port_groups: dict[tuple, tuple[Optional[datetime], tuple]] = {}
    no_port_groups: dict[tuple, tuple[Optional[datetime], tuple]] = {}

    for event in relevant:
        if event.source_ip and event.port is not None:
            base = ("port", event.source_ip, event.username, event.port)
            previous = port_groups.get(base)
            if (
                previous is not None
                and previous[0] is not None
                and event.timestamp is not None
                and timedelta(0)
                <= event.timestamp - previous[0]
                <= timedelta(seconds=60)
            ):
                key = previous[1]
            else:
                key = ("port_line", event.source_ip, event.username, event.line_number)
                port_groups[base] = (event.timestamp, key)
        elif event.source_ip:
            base = ("no_port", event.source_ip, event.username)
            previous = no_port_groups.get(base)
            if (
                previous is not None
                and previous[0] is not None
                and event.timestamp is not None
                and timedelta(0)
                <= event.timestamp - previous[0]
                <= timedelta(seconds=5)
            ):
                key = previous[1]
            else:
                key = ("no_port_line", event.source_ip, event.username, event.line_number)
                no_port_groups[base] = (event.timestamp, key)
        else:
            key = ("line", event.line_number)
        groups.setdefault(key, []).append(event)

    return list(groups.values())


class Detector:
    """Evaluate event-level and time-window detection rules."""

    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        self.config = config or DetectionConfig()

    def detect(self, events: list[Event]) -> DetectionResult:
        auth_events = [e for e in events if e.event_type in AUTH_EVENT_TYPES]
        failures = [e for e in auth_events if e.event_type == EVENT_FAILED_LOGIN]
        successes = [
            e for e in auth_events if e.event_type == EVENT_SUCCESSFUL_LOGIN
        ]

        valid_failures = [
            e for e in failures if e.source_ip is not None and e.timestamp is not None
        ]
        valid_successes = [
            e for e in successes if e.source_ip is not None and e.timestamp is not None
        ]

        failures_by_ip: dict[str, list[Event]] = defaultdict(list)
        successes_by_ip: dict[str, list[Event]] = defaultdict(list)
        for event in valid_failures:
            failures_by_ip[event.source_ip].append(event)
        for event in valid_successes:
            successes_by_ip[event.source_ip].append(event)
        for bucket in (*failures_by_ip.values(), *successes_by_ip.values()):
            bucket.sort(key=_event_sort_key)

        alerts: list[Alert] = []
        covered: set[Event] = set()

        # R002 / R003 -- repeated and high-volume failures per source IP.
        for source_ip, ip_failures in failures_by_ip.items():
            clusters = self._find_failure_clusters(ip_failures)
            for cluster in clusters:
                best = max(
                    cluster.candidates,
                    key=lambda item: (
                        item[2],
                        -(
                            ip_failures[item[1]].timestamp
                            - ip_failures[item[0]].timestamp
                        ).total_seconds(),
                        -item[0],
                    ),
                )
                window_events = ip_failures[best[0] : best[1] + 1]
                covered.update(ip_failures[cluster.start : cluster.end + 1])
                alerts.append(self._failure_alert(source_ip, window_events))

        # R004 -- invalid username attempts.
        invalid_groups = group_invalid_user_attempts(auth_events)
        for group in invalid_groups:
            usable = [
                e for e in group if e.source_ip is not None and e.timestamp is not None
            ]
            if not usable:
                continue
            representative = usable[0]
            failure_count = sum(
                1 for e in group if e.event_type == EVENT_FAILED_LOGIN
            )
            evidence = sorted(group, key=_event_sort_key)
            covered.update(group)
            alerts.append(
                Alert(
                    alert_id="",
                    rule_id="R004",
                    rule_name=RULES["R004"].name,
                    severity=RULES["R004"].severity,
                    timestamp=representative.timestamp,
                    source_ip=representative.source_ip,
                    usernames=_usernames(group),
                    failure_count=failure_count,
                    window_start=min(
                        (e.timestamp for e in usable if e.timestamp),
                        default=None,
                    ),
                    window_end=max(
                        (e.timestamp for e in usable if e.timestamp),
                        default=None,
                    ),
                    reason=(
                        f"Authentication attempt for username "
                        f"{representative.username!r} reported as invalid by sshd "
                        f"({len(group)} related log line(s)). This may indicate "
                        "account enumeration or a mistyped username."
                    ),
                    analyst_action=RULES["R004"].analyst_action,
                    mitre_attack=_mitre("T1110.001"),
                    evidence=evidence,
                )
            )

        # R005 -- failures followed by a successful login from the same IP.
        for source_ip, ip_successes in successes_by_ip.items():
            ip_failures = failures_by_ip.get(source_ip, [])
            previous_success: Optional[datetime] = None
            for success in ip_successes:
                if success.timestamp is None:  # defensive; filtered above
                    continue
                window_start = success.timestamp - timedelta(
                    seconds=self.config.window_seconds
                )
                preceding = [
                    failure
                    for failure in ip_failures
                    if (
                        (previous_success is None or failure.timestamp > previous_success)
                        and window_start <= failure.timestamp <= success.timestamp
                    )
                ]
                if len(preceding) >= self.config.failure_threshold:
                    evidence = preceding + [success]
                    covered.update(preceding)
                    covered.add(success)
                    alerts.append(
                        Alert(
                            alert_id="",
                            rule_id="R005",
                            rule_name=RULES["R005"].name,
                            severity=RULES["R005"].severity,
                            timestamp=success.timestamp,
                            source_ip=source_ip,
                            usernames=_usernames(evidence),
                            failure_count=len(preceding),
                            window_start=preceding[0].timestamp,
                            window_end=success.timestamp,
                            reason=(
                                f"{len(preceding)} failed authentication attempts "
                                f"from {source_ip} within "
                                f"{self._window_minutes():g} minutes were followed "
                                f"by a successful login for "
                                f"{success.username or 'an unknown user'!r}. "
                                "A successful login after repeated failures may "
                                "indicate password guessing that succeeded."
                            ),
                            analyst_action=RULES["R005"].analyst_action,
                            mitre_attack=_mitre("T1110.001", "T1078"),
                            evidence=evidence,
                        )
                    )
                previous_success = success.timestamp

        # R001 -- isolated failures not already represented in a higher alert.
        if self.config.include_single_failures:
            for failure in valid_failures:
                if failure in covered:
                    continue
                alerts.append(
                    Alert(
                        alert_id="",
                        rule_id="R001",
                        rule_name=RULES["R001"].name,
                        severity=RULES["R001"].severity,
                        timestamp=failure.timestamp,
                        source_ip=failure.source_ip,
                        usernames=_usernames([failure]),
                        failure_count=1,
                        window_start=failure.timestamp,
                        window_end=failure.timestamp,
                        reason=(
                            f"One failed SSH authentication attempt from "
                            f"{failure.source_ip}"
                            + (
                                f" for username {failure.username!r}"
                                if failure.username
                                else ""
                            )
                            + ". A single failure is a routine event."
                        ),
                        analyst_action=RULES["R001"].analyst_action,
                        mitre_attack=[],
                        evidence=[failure],
                    )
                )

        alerts.sort(
            key=lambda alert: (
                SEVERITY_ORDER.get(alert.severity, 99),
                alert.timestamp or datetime.min,
                alert.source_ip or "",
                alert.rule_id,
            )
        )
        alerts = [
            replace(alert, alert_id=f"ALT-{index:04d}")
            for index, alert in enumerate(alerts, start=1)
        ]

        skipped = sum(
            1
            for event in auth_events
            if event.event_type
            in (EVENT_FAILED_LOGIN, EVENT_SUCCESSFUL_LOGIN, EVENT_INVALID_USER)
            and (event.source_ip is None or event.timestamp is None)
        )

        sources = self._build_source_summary(
            auth_events, invalid_groups, alerts
        )

        return DetectionResult(
            alerts=alerts,
            sources=sources,
            invalid_user_attempts=len(invalid_groups),
            skipped_events_missing_fields=skipped,
            failures_analyzed=len(failures),
            successes_analyzed=len(successes),
        )

    # -- helpers -----------------------------------------------------------
    def _window_minutes(self) -> float:
        return self.config.window_seconds / 60

    def _find_failure_clusters(
        self, events: list[Event]
    ) -> list[_FailureCluster]:
        """Find maximal windows meeting the repeated-failure threshold.

        A two-pointer scan produces every qualifying window; overlapping
        windows are merged so a burst yields one alert rather than one alert
        per sliding position.  Severity is based on the largest single window,
        never on the merged span, so the rule window remains honest.
        """
        threshold = self.config.failure_threshold
        window_seconds = self.config.window_seconds
        candidates: list[tuple[int, int, int]] = []
        end = 0

        for start in range(len(events)):
            end = max(end, start)
            while (
                end + 1 < len(events)
                and (events[end + 1].timestamp - events[start].timestamp).total_seconds()
                <= window_seconds
            ):
                end += 1
            count = end - start + 1
            if count >= threshold:
                candidates.append((start, end, count))

        clusters: list[_FailureCluster] = []
        for start, end, count in candidates:
            if clusters and start <= clusters[-1].end:
                clusters[-1].end = max(clusters[-1].end, end)
                clusters[-1].candidates.append((start, end, count))
            else:
                clusters.append(
                    _FailureCluster(
                        start=start,
                        end=end,
                        candidates=[(start, end, count)],
                    )
                )
        return clusters

    def _failure_alert(self, source_ip: str, events: list[Event]) -> Alert:
        count = len(events)
        high = count >= self.config.high_volume_threshold
        rule = RULES["R003"] if high else RULES["R002"]
        severity = rule.severity
        window_start = events[0].timestamp
        window_end = events[-1].timestamp
        threshold_text = (
            f"high-volume threshold ({self.config.high_volume_threshold})"
            if high
            else f"repeated-failure threshold ({self.config.failure_threshold})"
        )
        return Alert(
            alert_id="",
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=severity,
            timestamp=window_start,
            source_ip=source_ip,
            usernames=_usernames(events),
            failure_count=count,
            window_start=window_start,
            window_end=window_end,
            reason=(
                f"{count} failed SSH authentication attempts from {source_ip} "
                f"within {self._window_minutes():g} minutes, meeting the "
                f"{threshold_text}. This may indicate password guessing, "
                "credential stuffing, or repeated user error."
            ),
            analyst_action=rule.analyst_action,
            mitre_attack=_mitre("T1110.001"),
            evidence=events,
        )

    @staticmethod
    def _build_source_summary(
        auth_events: list[Event],
        invalid_groups: list[list[Event]],
        alerts: list[Alert],
    ) -> list[dict]:
        summary: dict[str, dict] = {}

        def row(source_ip: str) -> dict:
            if source_ip not in summary:
                summary[source_ip] = {
                    "source_ip": source_ip,
                    "failed_logins": 0,
                    "successful_logins": 0,
                    "invalid_user_attempts": 0,
                    "usernames": set(),
                    "first_seen": None,
                    "last_seen": None,
                    "alerts": 0,
                }
            return summary[source_ip]

        for event in auth_events:
            if not event.source_ip:
                continue
            if event.event_type == EVENT_FAILED_LOGIN:
                entry = row(event.source_ip)
                entry["failed_logins"] += 1
            elif event.event_type == EVENT_SUCCESSFUL_LOGIN:
                entry = row(event.source_ip)
                entry["successful_logins"] += 1
            elif event.event_type == EVENT_INVALID_USER:
                entry = row(event.source_ip)
            else:
                continue
            if event.username:
                entry["usernames"].add(event.username)
            if event.timestamp is not None:
                if entry["first_seen"] is None or event.timestamp < entry["first_seen"]:
                    entry["first_seen"] = event.timestamp
                if entry["last_seen"] is None or event.timestamp > entry["last_seen"]:
                    entry["last_seen"] = event.timestamp

        for group in invalid_groups:
            source_ip = next(
                (event.source_ip for event in group if event.source_ip), None
            )
            if source_ip:
                row(source_ip)["invalid_user_attempts"] += 1

        for alert in alerts:
            if alert.source_ip in summary:
                summary[alert.source_ip]["alerts"] += 1

        rows = []
        for entry in summary.values():
            rows.append(
                {
                    "source_ip": entry["source_ip"],
                    "failed_logins": entry["failed_logins"],
                    "successful_logins": entry["successful_logins"],
                    "invalid_user_attempts": entry["invalid_user_attempts"],
                    "usernames": sorted(entry["usernames"]),
                    "first_seen": format_timestamp(entry["first_seen"]),
                    "last_seen": format_timestamp(entry["last_seen"]),
                    "alerts": entry["alerts"],
                }
            )
        rows.sort(key=lambda item: (-item["failed_logins"], item["source_ip"]))
        return rows
