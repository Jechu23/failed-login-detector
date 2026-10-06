#!/usr/bin/env python3
"""SSH failed-login detector.

Parses OpenSSH "Failed password" events from journalctl/syslog output,
groups them into bursts per source IP and flags likely brute-force or
username-enumeration activity (MITRE ATT&CK T1110 - Brute Force).
"""
import argparse
import csv
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Timestamp: journalctl default ("Oct 06 16:09:28") or short-iso ("2026-10-06T16:09:28")
TS = r"(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
FAILED_RE = re.compile(
    TS + r".*sshd\[\d+\]: Failed password for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+"
)


@dataclass
class Event:
    time: datetime
    ip: str
    user: str
    invalid_user: bool


@dataclass
class Burst:
    ip: str
    events: list = field(default_factory=list)

    @property
    def start(self):
        return self.events[0].time

    @property
    def end(self):
        return self.events[-1].time

    @property
    def attempts(self):
        return len(self.events)

    @property
    def users(self):
        return sorted({e.user for e in self.events})


def parse_timestamp(ts, year):
    """Convert a log timestamp to datetime (journalctl default has no year)."""
    if "T" in ts:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_log(lines, year):
    """Return a list of Event objects for every 'Failed password' line."""
    events = []
    for line in lines:
        match = FAILED_RE.search(line)
        if match:
            events.append(
                Event(
                    time=parse_timestamp(match.group("ts"), year),
                    ip=match.group("ip"),
                    user=match.group("user"),
                    invalid_user=bool(match.group("invalid")),
                )
            )
    return events


def group_bursts(events, window_minutes):
    """Group failures per IP: gaps shorter than the window belong to one burst."""
    by_ip = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)

    window = timedelta(minutes=window_minutes)
    bursts = []
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.time)
        current = Burst(ip=ip, events=[ip_events[0]])
        for event in ip_events[1:]:
            if event.time - current.events[-1].time <= window:
                current.events.append(event)
            else:
                bursts.append(current)
                current = Burst(ip=ip, events=[event])
        bursts.append(current)
    return sorted(bursts, key=lambda b: b.start)


def assess(burst, threshold):
    """Return (severity, indicators) for a burst, or (None, []) if below threshold."""
    if burst.attempts < threshold:
        return None, []
    indicators = ["password guessing"]
    if len(burst.users) >= 3:
        indicators.append("username enumeration")
    if "root" in burst.users:
        indicators.append("root targeted")
    high = burst.attempts >= threshold * 2 or len(burst.users) >= 5
    return ("HIGH" if high else "MEDIUM"), indicators


def build_report(bursts, threshold):
    rows = []
    for burst in bursts:
        severity, indicators = assess(burst, threshold)
        if severity:
            rows.append(
                {
                    "ip": burst.ip,
                    "start": burst.start.strftime("%Y-%m-%d %H:%M:%S"),
                    "end": burst.end.strftime("%Y-%m-%d %H:%M:%S"),
                    "attempts": burst.attempts,
                    "distinct_users": len(burst.users),
                    "users": ";".join(burst.users),
                    "severity": severity,
                    "indicators": ";".join(indicators),
                }
            )
    return rows


def print_report(events, rows):
    print("SSH failed-login report")
    print(f"Events parsed: {len(events)}   Source IPs: {len({e.ip for e in events})}   Alerts: {len(rows)}\n")
    if not rows:
        print("No bursts above the threshold.")
        return
    header = f"{'IP':<15} {'START':<19} {'END':<19} {'TRIES':>5} {'USERS':>5}  {'SEVERITY':<8} INDICATORS"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['ip']:<15} {r['start']:<19} {r['end']:<19} {r['attempts']:>5} "
            f"{r['distinct_users']:>5}  {r['severity']:<8} {r['indicators'].replace(';', ', ')}"
        )


def write_csv(rows, path):
    fields = ["ip", "start", "end", "attempts", "distinct_users", "users", "severity", "indicators"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Detect SSH brute-force bursts in auth logs.")
    parser.add_argument("logfile", help="log file path, or - for stdin")
    parser.add_argument("--threshold", type=int, default=5, help="failed attempts per burst to raise an alert (default 5)")
    parser.add_argument("--window", type=int, default=5, help="minutes of silence that end a burst (default 5)")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="year for logs without one (default current year)")
    parser.add_argument("--csv", help="also write the alerts to this CSV file")
    args = parser.parse_args(argv)

    handle = sys.stdin if args.logfile == "-" else open(args.logfile, encoding="utf-8", errors="replace")
    with handle:
        events = parse_log(handle, args.year)

    rows = build_report(group_bursts(events, args.window), args.threshold)
    print_report(events, rows)
    if args.csv:
        write_csv(rows, args.csv)
        print(f"\nAlerts written to {args.csv}")


if __name__ == "__main__":
    main()
