"""
simulator.py
------------
Generates a synthetic Windows Security / Sysmon / Firewall log stream containing
benign noise plus five injected MITRE ATT&CK attack scenarios.

This does NOT touch a real system, exploit anything, or send network traffic.
It only writes structured JSON-lines events to logs/events.jsonl for the
detector to analyze. Safe to run anywhere.
"""

import json
import random
import uuid
from datetime import datetime, timedelta, timezone

random.seed(42)  # reproducible output for the README sample

START_TIME = datetime(2026, 8, 20, 9, 0, 0, tzinfo=timezone.utc)

USERS = ["j.morgan", "s.patel", "a.chen", "r.diaz", "svc_backup", "svc_sql"]
WORKSTATIONS = ["WKS-101", "WKS-114", "WKS-207", "SRV-DC01", "SRV-APP02"]
LEGIT_PROCESSES = ["explorer.exe", "chrome.exe", "outlook.exe", "teams.exe", "winword.exe"]


def _event(ts, channel, event_id, **fields):
    return {
        "id": uuid.uuid4().hex[:12],
        "timestamp": ts.isoformat(),
        "channel": channel,
        "event_id": event_id,
        **fields,
    }


def generate_benign_noise(start, count=250):
    events = []
    t = start
    for _ in range(count):
        t += timedelta(seconds=random.randint(1, 20))
        choice = random.random()
        user = random.choice(USERS)
        ws = random.choice(WORKSTATIONS)

        if choice < 0.35:
            events.append(_event(t, "Security", 4624, account=user, src_ip=f"10.0.1.{random.randint(2,60)}",
                                  logon_type=random.choice([2, 3, 10]), workstation=ws))
        elif choice < 0.55:
            events.append(_event(t, "Sysmon", 1, image=f"C:\\Program Files\\App\\{random.choice(LEGIT_PROCESSES)}",
                                  command_line=random.choice(LEGIT_PROCESSES), parent_image="explorer.exe", user=user))
        elif choice < 0.75:
            events.append(_event(t, "Sysmon", 3, image="chrome.exe", src_ip=f"10.0.1.{random.randint(2,60)}",
                                  dst_ip=f"142.250.{random.randint(1,255)}.{random.randint(1,255)}",
                                  dst_port=443))
        elif choice < 0.9:
            events.append(_event(t, "Security", 4769, account=user, service_name="krbtgt",
                                  ticket_encryption_type="0x12", client_ip=f"10.0.1.{random.randint(2,60)}"))
        else:
            events.append(_event(t, "Sysmon", 10, source_image="MsMpEng.exe", target_image="C:\\Windows\\System32\\lsass.exe",
                                  granted_access="0x1000"))
    return events


def inject_brute_force(start):
    """T1110.001 - Password Guessing followed by a successful logon."""
    events = []
    t = start
    target_user = "s.patel"
    attacker_ip = "203.0.113.44"
    for _ in range(7):
        t += timedelta(seconds=random.randint(3, 8))
        events.append(_event(t, "Security", 4625, account=target_user, src_ip=attacker_ip,
                              logon_type=3, workstation="WKS-114"))
    t += timedelta(seconds=15)
    events.append(_event(t, "Security", 4624, account=target_user, src_ip=attacker_ip,
                          logon_type=3, workstation="WKS-114"))
    return events


def inject_kerberoasting(start):
    """T1558.003 - Multiple TGS requests for different SPNs using RC4 (0x17)."""
    events = []
    t = start
    account = "svc_sql"
    services = ["MSSQLSvc/db01.corp.local", "HTTP/app02.corp.local", "CIFS/fs01.corp.local", "LDAP/dc01.corp.local"]
    for svc in services:
        t += timedelta(seconds=random.randint(1, 4))
        events.append(_event(t, "Security", 4769, account=account, service_name=svc,
                              ticket_encryption_type="0x17", client_ip="10.0.1.55"))
    return events


def inject_powershell_encoded(start):
    """T1059.001 - PowerShell with a base64-encoded command."""
    t = start + timedelta(seconds=5)
    encoded = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA..."
    return [_event(t, "Sysmon", 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    command_line=f"powershell.exe -NoP -W Hidden -Enc {encoded}",
                    parent_image="winword.exe", user="a.chen")]


def inject_port_scan(start):
    """T1046 - Network Service Discovery: one host sweeping many ports quickly."""
    events = []
    t = start
    src = "10.0.1.55"
    dst = "10.0.1.10"
    for port in [21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 8080, 8443]:
        t += timedelta(milliseconds=random.randint(200, 900))
        events.append(_event(t, "Sysmon", 3, image="nmap.exe" if random.random() < 0.3 else "svchost.exe",
                              src_ip=src, dst_ip=dst, dst_port=port))
    return events


def inject_credential_dumping(start):
    """T1003.001 - Suspicious process requesting high-privilege access to lsass.exe."""
    t = start + timedelta(seconds=2)
    return [_event(t, "Sysmon", 10, source_image="C:\\Users\\Public\\update.exe",
                    target_image="C:\\Windows\\System32\\lsass.exe", granted_access="0x1410")]


def build_timeline():
    all_events = []
    t = START_TIME
    all_events += generate_benign_noise(t, count=250)

    t += timedelta(minutes=12)
    all_events += inject_brute_force(t)

    t += timedelta(minutes=8)
    all_events += inject_kerberoasting(t)

    t += timedelta(minutes=6)
    all_events += inject_powershell_encoded(t)

    t += timedelta(minutes=4)
    all_events += inject_port_scan(t)

    t += timedelta(minutes=5)
    all_events += inject_credential_dumping(t)

    all_events += generate_benign_noise(t + timedelta(minutes=10), count=100)

    all_events.sort(key=lambda e: e["timestamp"])
    return all_events


def main():
    events = build_timeline()
    out_path = "logs/events.jsonl"
    with open(out_path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(f"Generated {len(events)} events -> {out_path}")


if __name__ == "__main__":
    main()
