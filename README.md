# Linux SOC Monitor

**Offline SSH authentication log analysis and triage for Linux.**

Linux SOC Monitor parses authentication logs, detects suspicious login patterns, and produces evidence-rich reports for investigation. It is a blue-team / SOC Analyst L1 portfolio project focused on log analysis, event correlation, alert triage, evidence handling, and reporting.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-71%20passed-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

> Alerts are investigation leads, not proof of compromise. Validate every finding against the original log and surrounding activity.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Sample output](#sample-output)
- [Command-line interface](#command-line-interface)
- [Detection rules](#detection-rules)
- [Input formats](#input-formats)
- [Report formats](#report-formats)
- [Analyzing real logs](#analyzing-real-logs)
- [Security and evidence handling](#security-and-evidence-handling)
- [Testing](#testing)
- [Walkthrough: raw evidence to triage](#walkthrough-raw-evidence-to-triage)
- [Project structure](#project-structure)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Publish to GitHub](#publish-to-github)
- [License](#license)

---

## Features

| Area | Capability |
| --- | --- |
| **Input** | Debian/Ubuntu `auth.log`, RHEL/Fedora `/var/log/secure`, and exported `journalctl` text |
| **Parsing** | SSH success/failure/invalid-user events, IPv4/IPv6, ports, auth methods, PAM lines, ISO and syslog timestamps |
| **Detection** | Repeated failures, high-volume failures, invalid usernames, and failure-then-success sequences |
| **Correlation** | Configurable time windows, strict per-source-IP isolation, grouped invalid-user attempts |
| **Triage** | Low/Medium/High severity, rule explanation, analyst action, MITRE ATT&CK references |
| **Evidence** | Original raw lines, normalized fields, input SHA-256, analysis time, complete JSON evidence |
| **Reporting** | Terminal summary, machine-readable JSON, one-row-per-alert CSV |
| **Safety** | Read-only inputs, no active response, terminal-injection protections, CSV formula-injection mitigation |
| **Runtime** | Python 3.9+ standard library only; `pytest` is used only for tests |

---

## How it works

```text
auth.log / secure / journalctl text
                │
                ▼
       app/log_parser.py
  timestamps · IP validation · PAM dedupe
                │
                ▼
        app/detector.py
  R001–R005 · per-IP windows · triage data
                │
                ▼
        app/reporter.py
   terminal · JSON · CSV evidence reports
```

1. **Read** one log file as a normal user.
2. **Parse** supported records into normalized events while preserving raw evidence.
3. **Detect** event-level and time-window rules.
4. **Triage** with severity, explanation, analyst action, and supporting events.
5. **Report** to the terminal or export JSON/CSV.

---

## Quick start

### Requirements

- Python **3.9+**
- Linux for analyzing local system logs (file analysis works on any OS with Python 3.9+)
- No runtime third-party packages

### Run immediately

```bash
git clone https://github.com/<your-username>/linux-soc-monitor.git
cd linux-soc-monitor

# No installation required for the analyzer itself
python3 -m app.main --file sample_logs/auth.log --year 2024
```

### Install test dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest
```

### Generate reports

```bash
# JSON report in reports/ (default destination)
python3 -m app.main --file sample_logs/auth.log --year 2024 --format json

# CSV report to an explicit path
python3 -m app.main --file sample_logs/auth.log --year 2024 \
  --format csv --output reports/sample_findings.csv
```

`python3 -m app ...` also works as a shorter entry point.

---

## Sample output

Excerpt from `python3 -m app.main --file sample_logs/auth.log --year 2024`. The full report contains 9 alerts: 2 High, 4 Medium, and 3 Low.

```text
LINUX SOC MONITOR
=================
Input file: sample_logs/auth.log
Input SHA-256: 3ea9add7a4c9705dd279cc73869d86999533f9373094c12d6d9c6ca0de7f3888
Analyzed at: 2026-10-31T18:09:50Z (UTC)
Assumed timezone for offset-less timestamps: UTC

SUMMARY
-------
Lines read:                       42
Events parsed:                    39
  Failed logins:                  21
  Successful logins:              5
  Invalid-user attempts:          3
  Non-auth lines:                 5
Unparsed lines:                   2
PAM duplicate lines removed:      1
Skipped events (missing fields):  1
Unique source IPs:                8
Alerts generated:                 9 (High 2, Medium 4, Low 3)
Observation window:               2024-01-15T08:00:04Z to 2024-01-15T10:06:00Z
Detection settings:               failure>=5, high>=10, window=5 min, single-failure alerts=on

ALERTS (9)
----------
[HIGH] Failure followed by successful login (R005)
  Alert ID: ALT-0001
  Source IP: 203.0.113.45
  Username(s): admin, deploy, oracle, root, test, ubuntu
  Window: 2024-01-15T09:00:01Z to 2024-01-15T09:01:02Z
  Reason: 6 failed authentication attempts from 203.0.113.45 within 5 minutes were followed by a successful login for 'deploy'. A successful login after repeated failures may indicate password guessing that succeeded.
  Analyst action: Treat the account as potentially compromised until validated. Confirm the login with the account owner, review session activity, and rotate credentials if suspicious.
  MITRE ATT&CK: T1110.001 Password Guessing; T1078 Valid Accounts
  Evidence (7 event(s)):
    - 2024-01-15T09:00:01Z event=failed_login user=admin ip=203.0.113.45 port=40001
      Jan 15 09:00:01 web01 sshd[9001]: Failed password for invalid user admin from 203.0.113.45 port 40001 ssh2
    - 2024-01-15T09:00:08Z event=failed_login user=oracle ip=203.0.113.45 port=40002
      Jan 15 09:00:08 web01 sshd[9002]: Failed password for invalid user oracle from 203.0.113.45 port 40002 ssh2
    ...
    - 2024-01-15T09:01:02Z event=successful_login user=deploy ip=203.0.113.45 port=40007
      Jan 15 09:01:02 web01 sshd[9007]: Accepted password for deploy from 203.0.113.45 port 40007 ssh2
```

JSON keeps every supporting event; CSV contains one row per alert with the raw evidence joined into a single field.

---

## Command-line interface

```text
python3 -m app.main --file PATH [options]
```

| Option | Default | Description |
| --- | --- | --- |
| `--file PATH`, `-f PATH` | **required** | Authentication log or exported `journalctl` text file. |
| `--format {text,json,csv}`, `-F` | `text` | Output format. |
| `--output PATH`, `-o PATH` | see below | Write to a file; use `-` for standard output. |
| `--threshold N` | `5` | Failures from one IP in the window that trigger R002. |
| `--high-threshold N` | `10` | Failures that escalate R003 to High; must be `>= --threshold`. |
| `--window MINUTES` | `5` | Correlation window for R002, R003, and R005. |
| `--year YYYY` | current UTC year | Year for syslog timestamps, which normally omit it (1970–9999). |
| `--assume-tz TZ` | `UTC` | IANA timezone for timestamps without an offset, e.g. `America/New_York`. |
| `--no-single-failures` | off | Suppress Low alerts for isolated failures. |
| `--no-color` | off | Disable ANSI colors in terminal output. |
| `--quiet` | off | Suppress the “report written to …” notice after writing a file. |
| `--help`, `-h` | — | Show help and exit. |
| `--version` | — | Print the version and exit. |

### Output destinations

| Format | No `--output` | With `--output -` |
| --- | --- | --- |
| `text` | Terminal | Terminal |
| `json` | `reports/soc_report_<UTC timestamp>.json` | Standard output |
| `csv` | `reports/soc_report_<UTC timestamp>.csv` | Standard output |

The `reports/` directory is created automatically. Explicit output paths overwrite the target file.

### Examples

```bash
# Analyze the included sample
python3 -m app.main --file sample_logs/auth.log --year 2024

# Analyze an exported journal
python3 -m app.main --file sample_logs/journal_export.log

# JSON to stdout for jq
python3 -m app.main --file sample_logs/auth.log --year 2024 \
  --format json --output - | jq '.summary'

# Tune thresholds and window
python3 -m app.main --file /tmp/auth-copy.log \
  --threshold 3 --high-threshold 8 --window 10

# Reduce Low-severity noise on a busy host
python3 -m app.main --file /tmp/auth-copy.log --no-single-failures

# Historical log with an assumed local timezone
python3 -m app.main --file /tmp/auth-2023.log \
  --year 2023 --assume-tz Europe/London

# Explicit CSV evidence file, quiet output
python3 -m app.main --file /tmp/auth-copy.log \
  --format csv --output reports/incident-2024-01-15.csv --quiet
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Analysis completed, including when alerts were generated. |
| `1` | Input/output/configuration error, e.g. missing file or unwritable output. |
| `2` | Invalid command-line arguments. |

---

## Detection rules

Defaults are configurable triage heuristics, not universal indicators of compromise.

| ID | Rule | Default logic | Severity |
| --- | --- | --- | --- |
| `R001` | Single failed SSH login | One failure not already represented in a higher alert | Low |
| `R002` | Repeated SSH authentication failures | ≥5 failures from one IP within 5 minutes | Medium |
| `R003` | High-volume SSH authentication failures | ≥10 failures from one IP within 5 minutes | High |
| `R004` | Invalid username authentication attempt | An attempt involving a username sshd reported as invalid | Medium |
| `R005` | Failure followed by successful login | ≥5 failures from the same IP in the window immediately before a success | High |

### Correlation behavior

- Correlation is **per source IP**. Events from different IPs are never combined.
- Windows are **inclusive**: an event exactly `window` seconds after the first still counts.
- Overlapping qualifying windows are merged into one burst, so a single attack produces one R002/R003 alert rather than many sliding-window duplicates.
- Severity uses the **largest single qualifying window**, not the merged span.
- R003 supersedes R002 for the same burst; both are not emitted.
- R001 is suppressed for failures already covered by a repeated-failure, invalid-user, or failure-then-success alert.
- R004 groups related `Invalid user ...` and `Failed password for invalid user ...` lines from the same source port and within 60 seconds into one attempt.
- R005 considers only failures after the previous successful login from that IP, avoiding duplicate sequence alerts for later successes.
- Alerts require a valid source IP and timestamp. Events missing either field are counted in `skipped_events_missing_fields`.
- Each alert preserves the supporting events and original raw lines.

### MITRE ATT&CK mapping

| Reference | Applied to | Justification |
| --- | --- | --- |
| [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | R002, R003, R004 | Repeated or invalid-name SSH failures are consistent with password guessing. |
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) | R005 | A success after repeated failures may indicate use of a valid account. |

R001 intentionally has no ATT&CK mapping: one failure alone does not justify a technique attribution.

---

## Input formats

Supported records have a leading timestamp, host, process, and message.

```text
# Debian/Ubuntu auth.log, RHEL/Fedora secure (syslog, no year)
Jan 15 09:00:01 web01 sshd[9001]: Failed password for root from 203.0.113.45 port 40003 ssh2

# journalctl -o short-iso / short-iso-precise export
2024-02-02T11:00:01+0000 db01 sshd[5001]: Failed password for root from 203.0.113.99 port 60001 ssh2
```

Recognized messages include:

- `Failed password|publickey|keyboard-interactive/pam|gssapi-with-mic|none ...`
- `Failed password for invalid user ...`
- `Accepted password|publickey|...`
- `Invalid user USER from IP [port N]`
- `error: maximum authentication attempts exceeded ...`
- `error: PAM: Authentication failure ...`
- `error: PAM: User not known ...`
- `pam_unix(sshd:auth): authentication failure; ... rhost=IP ... user=USER`
- Connection lifecycle: `Connection from`, `Connection closed by`, `Disconnected from`, `Received disconnect from`, missing-identification messages

### Timestamps

Supported forms:

- Syslog: `Jan 15 09:00:01`
- ISO-8601: `2024-02-02T11:00:01Z`, `2024-02-02T11:00:01+0000`, `2024-02-02T11:00:01-05:00`
- Optional fractional seconds: `2024-02-02T11:00:01.123456Z`
- Space-separated ISO: `2024-02-02 11:00:01`

Parsed timestamps are normalized to UTC. The original timestamp string and raw line are retained.

Syslog timestamps omit the year and timezone:

- `--year` supplies the year (default: current UTC year).
- `--assume-tz` supplies the timezone for offset-less values.
- A backwards jump of more than 180 days is treated as a New Year rollover.
- ISO timestamps with an explicit offset ignore `--assume-tz`.

### Parser resilience

- IPv4 and IPv6 addresses are validated and canonicalized.
- Invalid addresses such as `not-an-ip` remain in the raw message but are not used for correlation.
- Matching `sshd` and `pam_unix` failure lines for the same user, IP, and second are deduplicated.
- Blank lines are counted separately.
- Malformed or unrelated lines do not crash the program; they are counted with reasons such as `missing_timestamp`, `malformed_timestamp`, and `unrecognized_structure`.
- Up to 10 unparsed samples and reason counts appear in JSON `parser_diagnostics`.
- Structurally valid non-auth lines such as sudo or cron messages are counted as non-auth events.

---

## Report formats

### JSON

Top-level sections:

| Section | Contents |
| --- | --- |
| `report` | Tool/version, generation time, input path, SHA-256, input format, detection parameters, disclaimer |
| `summary` | Counts, auth results, source IPs, alert totals, time range, analysis duration |
| `alerts` | Ordered findings with rule metadata, severity, reason, analyst action, MITRE references, and full evidence |
| `sources` | Per-IP failure/success/invalid-attempt counts, usernames, first/last seen, alert count |
| `parser_diagnostics` | Unparsed-line reasons and samples |

Alert IDs (`ALT-0001`, `ALT-0002`, …) are deterministic for a run and ordered by severity, then time.

Each alert contains:

```text
alert_id, rule_id, rule_name, severity, timestamp, source_ip, usernames,
failure_count, window_start, window_end, reason, analyst_action,
mitre_attack, evidence_count, evidence
```

Each evidence event includes the line number, normalized and raw timestamps, event type, username, IP, port, auth method, invalid-user flag, hostname, process, PID, component, message, and complete raw line.

### CSV

One row per alert with these columns:

```text
alert_id, rule_id, rule_name, severity, timestamp, source_ip, usernames,
failure_count, window_start, window_end, mitre_attack, reason,
analyst_action, evidence_count, evidence
```

The `evidence` field contains raw supporting log lines joined with ` | `. Use JSON when structured per-event evidence is preferred.

---

## Analyzing real logs

Run the analyzer as an unprivileged user. Export or copy protected logs, then analyze the copy.

```bash
# Debian/Ubuntu
sudo cp /var/log/auth.log /tmp/auth-copy.log
sudo chown "$USER" /tmp/auth-copy.log

# RHEL/Fedora
sudo cp /var/log/secure /tmp/auth-copy.log
sudo chown "$USER" /tmp/auth-copy.log

# systemd journal export
journalctl -o short-iso > /tmp/journal-export.log

# Analyze the copy
python3 -m app.main --file /tmp/auth-copy.log --format json
python3 -m app.main --file /tmp/journal-export.log
```

Do not run the analyzer as root. Delete temporary copies when finished, and redact usernames, hostnames, and IP addresses before publishing reports.

---

## Security and evidence handling

- Source files are opened read-only and never modified or deleted.
- The input is read once; its SHA-256 is recorded so the report describes exactly the bytes analyzed.
- The input filename and analysis time are recorded in every report.
- Every alert retains its supporting normalized events and original raw lines.
- Terminal output escapes control characters from log-derived fields to reduce terminal-injection risk.
- CSV usernames beginning with spreadsheet formula characters are prefixed defensively.
- Generated reports may contain sensitive usernames, hostnames, and IP addresses. Treat them as investigation artifacts and redact before publishing.
- No credentials, secrets, or private keys are required or stored.
- The tool performs no active response: no IP blocking, account disabling, or authentication changes.
- All bundled sample data is synthetic; IPs come from RFC 5737 and RFC 3849 documentation ranges.

---

## Testing

```bash
pip install -r requirements.txt
python3 -m pytest
```

```text
71 passed
```

Coverage includes parser normalization and tolerance, PAM deduplication, IP/timestamp validation, detection thresholds and window boundaries, per-IP isolation, invalid-user grouping, failure-then-success correlation, evidence retention, text/JSON/CSV rendering, CLI behavior, exit codes, and the module entry point.

<details>
<summary><strong>Specification acceptance checklist</strong></summary>

- [x] Reads a supported sample authentication log.
- [x] Parses supported failed and successful SSH events correctly.
- [x] Handles malformed or unrelated lines without crashing.
- [x] Detects repeated failures from one source with a configurable window.
- [x] Does not combine events from different source IPs.
- [x] Flags failure-followed-by-success only when correlation conditions match.
- [x] Generates JSON and CSV reports with expected fields.
- [x] Includes tests for parser, detection, reporting, and CLI behavior.
- [x] Documents installation, usage, sample output, assumptions, and limitations.
- [x] Includes a raw-evidence-to-triage demonstration.

</details>

---

## Walkthrough: raw evidence to triage

Reproduce the lead alert:

```bash
python3 -m app.main --file sample_logs/auth.log --year 2024
```

1. **Raw evidence.** Six failed SSH attempts from `203.0.113.45` occur between `09:00:01` and `09:00:39` for `admin`, `oracle`, `root`, `ubuntu`, and `test`. Some use invalid usernames. At `09:01:02`, a successful password login occurs for `deploy` from the same IP.
2. **Rule evaluation.**
   - **R002:** 6 failures within 61 seconds exceeds the 5-in-5-minutes threshold.
   - **R004:** `admin` and `oracle` were reported as invalid usernames.
   - **R005:** 6 failures immediately precede a successful login from the same IP.
3. **Triage.** Confirm with the `deploy` account owner whether the login was expected. Verify the source against VPN, jump-host, and asset records. Review that account's session history after `09:01:02`. If unexplained, treat the account as compromised and rotate credentials. The alert is a lead — the same pattern can come from a legitimate user repeatedly mistyping a password.
4. **Evidence.** Re-run with `--format json` to retain every raw event and the input SHA-256, then attach the report to the investigation record.

The second synthetic source (`198.51.100.77`, 11 failures in 150 seconds) demonstrates R003 high-volume escalation. The malformed line with `from not-an-ip` is parsed but not used, and the summary reports one skipped event.

---

## Project structure

```text
linux-soc-monitor/
├── app/
│   ├── __init__.py          # version metadata
│   ├── __main__.py          # python3 -m app entry point
│   ├── main.py              # CLI, orchestration, output handling
│   ├── log_parser.py        # timestamp/message parsing and normalization
│   ├── detector.py          # rules, correlation, triage metadata
│   └── reporter.py          # text, JSON, CSV reports
├── sample_logs/
│   ├── auth.log             # synthetic syslog sample
│   ├── journal_export.log   # synthetic journalctl sample
│   └── README.md            # sample data provenance
├── reports/                 # default output directory (.gitkeep only)
├── tests/
│   ├── event_factory.py
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_reporter.py
│   └── test_cli.py
├── requirements.txt
├── pytest.ini
├── README.md
├── .gitignore
└── LICENSE
```

---

## Limitations

This is an offline MVP for triage, not a SIEM.

- **Text exports only.** `journalctl -o json`, compressed journals, and `journalctl -o cat` (no timestamps) are not supported.
- **SSH authentication focus.** sudo, account changes, service changes, and other Linux telemetry are out of scope.
- **Common English sshd wording.** Unusual or localized daemon messages may be treated as unrelated.
- **Conservative PAM deduplication.** Matching requires the same user, IP, and log second; different timestamp precision can leave duplicates.
- **Source IP correlation only.** Shared NAT/proxy addresses can mix users, and distributed attacks across many IPs do not aggregate.
- **One file per run.** Rotated logs are not automatically concatenated.
- **Lab-sized memory profile.** The whole file is loaded as normalized events.
- **High alert volume is possible** on busy systems; use `--no-single-failures`.
- **No active response.** The tool never blocks IPs, disables accounts, or changes authentication settings.
- **Alerts are leads.** False positives are expected; validate with account owners, asset inventory, session logs, and change records.

---

## Roadmap

- Live journal follow mode with safe checkpointing.
- sudo, account-change, and service telemetry.
- Detection across rotating log files.
- Additional correlation keys (username, host, ASN) with explicit opt-in.
- STIX/CEF export and Wazuh/SIEM integration.
- A small web dashboard.
- MITRE technique IDs verified against the current official documentation.

---

## Publish to GitHub

This repository is already initialized locally. Before pushing, set your Git identity and amend the initial commit if needed:

```bash
git config user.name "Your Name"
git config user.email "you@example.com"

# Only needed if the existing commit uses a placeholder author
git commit --amend --reset-author --no-edit
```

Create an **empty** repository on GitHub named `linux-soc-monitor` (do not initialize it with a README, license, or `.gitignore`), then connect and push:

### HTTPS

```bash
git remote add origin https://github.com/<your-username>/linux-soc-monitor.git
git branch -M main
git push -u origin main
```

### SSH

```bash
git remote add origin git@github.com:<your-username>/linux-soc-monitor.git
git branch -M main
git push -u origin main
```

### GitHub CLI

```bash
gh auth login
gh repo create linux-soc-monitor --public --source=. --remote=origin --push
```

### If the remote already exists

```bash
git remote set-url origin <repository-url>
git push -u origin main
```

Verify the result:

```bash
git remote -v
git status
git log --oneline
```

Generated reports and Python caches are excluded by `.gitignore`. The bundled sample logs are synthetic and safe to publish.

---

## License

MIT — see [LICENSE](LICENSE).
