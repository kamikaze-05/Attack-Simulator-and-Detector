"""
detector.py
-----------
Reads logs/events.jsonl, runs every rule in rules.py against the event
stream, and prints/saves any resulting MITRE ATT&CK-mapped alerts.
"""

import json
from rules import ALL_DETECTORS

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_events(path="logs/events.jsonl"):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    events.sort(key=lambda e: e["timestamp"])
    return events


def run_detectors(events):
    alerts = []
    for detector in ALL_DETECTORS:
        alerts.extend(detector(events))
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.get("severity", "low"), 9))
    return alerts


def print_alerts(alerts):
    if not alerts:
        print("No alerts triggered.")
        return
    print(f"\n{len(alerts)} ALERT(S) TRIGGERED\n" + "=" * 60)
    for a in alerts:
        print(f"[{a['severity'].upper():^8}] {a['title']}  ({a['id']} - {a['tactic']})")
        print(f"           {a['evidence']}")
        print("-" * 60)


def main():
    events = load_events()
    print(f"Loaded {len(events)} events for analysis...")
    alerts = run_detectors(events)
    print_alerts(alerts)

    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\nSaved {len(alerts)} alerts -> alerts.json")


if __name__ == "__main__":
    main()
