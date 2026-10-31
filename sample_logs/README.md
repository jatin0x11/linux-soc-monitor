# Sample logs

These files are synthetic and safe to publish. No real accounts, hosts, or
addresses are present. IP addresses are from the documentation ranges reserved
by RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or from
`2001:db8::/32`; they do not identify real systems.

| File | Purpose |
| --- | --- |
| `auth.log` | Syslog-style Debian/Ubuntu authentication log with benign activity, a medium burst, a high-volume burst, invalid-user attempts, a failure-then-success sequence, a PAM duplicate, an IPv6 event, and malformed lines. |
| `journal_export.log` | `journalctl -o short-iso`-style export with ISO-8601 timestamps. |

`auth.log` uses the traditional syslog format, which omits the year. For a
reproducible demonstration, pass `--year 2024`:

```bash
python3 -m app.main --file sample_logs/auth.log --year 2024
```

The same file works without `--year`; timestamps are then assigned the current
UTC year.

`journal_export.log` contains explicit dates and can be analyzed directly:

```bash
python3 -m app.main --file sample_logs/journal_export.log
```
