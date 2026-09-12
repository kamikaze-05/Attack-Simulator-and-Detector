"""
rules.py
--------
Each rule = metadata loaded from rules/*.yml + a small detection function.
Detection functions take the full sorted event list and return a list of
alert dicts. Keeping metadata in YAML (Sigma-style) makes rules easy to skim,
extend, or eventually port to a real Sigma-compatible engine.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False


def _load_meta(path):
    """Minimal YAML loader fallback so the project has zero hard dependencies."""
    if _HAVE_YAML:
        with open(path) as f:
            return yaml.safe_load(f)
    meta = {}
    with open(path) as f:
        text = f.read()
    for key in ("title", "id", "tactic", "severity"):
        m = re.search(rf"^{key}:\s*(.+)$", text, re.MULTILINE)
        if m:
            meta[key] = m.group(1).strip()
    desc = re.search(r"description:\s*>\s*\n(.*?)(?=\n\S|\Z)", text, re.DOTALL)
    meta["description"] = " ".join(l.strip() for l in desc.group(1).splitlines()).strip() if desc else ""
    return meta


def _ts(e):
    return datetime.fromisoformat(e["timestamp"])


def detect_brute_force(events):
    meta = _load_meta("rules/brute_force.yml")
    failures = defaultdict(list)  # (account, src_ip) -> [timestamps]
    alerts = []
    for e in events:
        if e["channel"] == "Security" and e["event_id"] == 4625:
            key = (e["account"], e["src_ip"])
            failures[key].append(_ts(e))
        elif e["channel"] == "Security" and e["event_id"] == 4624:
            key = (e["account"], e["src_ip"])
            recent_failures = [t for t in failures.get(key, []) if _ts(e) - t <= timedelta(seconds=300)]
            if len(recent_failures) >= 5:
                alerts.append({
                    **meta,
                    "matched_account": e["account"],
                    "matched_src_ip": e["src_ip"],
                    "evidence": f"{len(recent_failures)} failed logons then a success at {e['timestamp']}",
                })
    return alerts


def detect_kerberoasting(events):
    meta = _load_meta("rules/kerberoasting.yml")
    by_account = defaultdict(list)
    for e in events:
        if e["channel"] == "Security" and e["event_id"] == 4769 and e.get("ticket_encryption_type") == "0x17":
            by_account[e["account"]].append(e)

    alerts = []
    for account, evs in by_account.items():
        evs.sort(key=lambda e: e["timestamp"])
        window = []
        seen_services = set()
        for e in evs:
            window = [w for w in window if _ts(e) - _ts(w) <= timedelta(seconds=60)] + [e]
            seen_services = {w["service_name"] for w in window}
            if len(seen_services) >= 3:
                alerts.append({
                    **meta,
                    "matched_account": account,
                    "evidence": f"{len(seen_services)} distinct RC4 TGS requests within 60s: {sorted(seen_services)}",
                })
                break
    return alerts


def detect_powershell_encoded(events):
    meta = _load_meta("rules/powershell_encoded.yml")
    alerts = []
    for e in events:
        if e["channel"] == "Sysmon" and e["event_id"] == 1 and "powershell.exe" in e.get("image", "").lower():
            cmd = e.get("command_line", "")
            if re.search(r"-enc(odedcommand)?\b", cmd, re.IGNORECASE):
                alerts.append({
                    **meta,
                    "matched_user": e.get("user"),
                    "evidence": f"Encoded command line: {cmd[:80]}...",
                })
    return alerts


def detect_port_scan(events):
    meta = _load_meta("rules/port_scan.yml")
    by_src = defaultdict(list)
    for e in events:
        if e["channel"] == "Sysmon" and e["event_id"] == 3:
            by_src[e["src_ip"]].append(e)

    alerts = []
    for src, evs in by_src.items():
        evs.sort(key=lambda e: e["timestamp"])
        window = []
        for e in evs:
            window = [w for w in window if _ts(e) - _ts(w) <= timedelta(seconds=10)] + [e]
            ports = {w["dst_port"] for w in window}
            if len(ports) >= 15:
                alerts.append({
                    **meta,
                    "matched_src_ip": src,
                    "evidence": f"{len(ports)} distinct destination ports within 10s: {sorted(ports)}",
                })
                break
    return alerts


ALLOWLISTED_LSASS_ACCESSORS = {"MsMpEng.exe", "wmiprvse.exe", "svchost.exe", "csrss.exe"}


def detect_credential_dumping(events):
    meta = _load_meta("rules/credential_dumping.yml")
    alerts = []
    for e in events:
        if e["channel"] == "Sysmon" and e["event_id"] == 10 and "lsass.exe" in e.get("target_image", "").lower():
            source = e.get("source_image", "")
            source_name = source.split("\\")[-1]
            if source_name not in ALLOWLISTED_LSASS_ACCESSORS and e.get("granted_access") in {"0x1010", "0x1410", "0x1438"}:
                alerts.append({
                    **meta,
                    "matched_process": source,
                    "evidence": f"GrantedAccess={e.get('granted_access')} to lsass.exe from {source}",
                })
    return alerts


ALL_DETECTORS = [
    detect_brute_force,
    detect_kerberoasting,
    detect_powershell_encoded,
    detect_port_scan,
    detect_credential_dumping,
]
