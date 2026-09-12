# Attack-Simulator-and-Detector


A lightweight, zero-dependency attack simulation and detection engine mapped to **MITRE ATT&CK**. It generates a synthetic Windows Security / Sysmon log stream containing realistic benign activity plus five injected attack techniques, then runs a small rule-based detection engine against that stream to identify each one.

Built to demonstrate both sides of the fence: understanding how an attack technique produces log evidence, and writing the detection logic that catches it.

> **Disclaimer:** This project does not touch a real system, exploit anything, or generate real network traffic. All "attacks" are synthetic JSON log events written to a local file for detection-engineering practice.

## Why this project

Most beginner security projects pick one side — either an offensive tool or a defensive one. This project pairs them: each simulated technique has a corresponding rule that explains *why* it's detectable, based on the actual log fields a real SIEM would see (Event ID 4625/4624, 4769, Sysmon 1/3/10).

## Architecture

```
simulator.py  -->  logs/events.jsonl  -->  detector.py  -->  alerts.json
   (attacker)         (raw log data)      (rules.py engine)     (SOC output)
```

- **`simulator.py`** — builds a ~1 hour timeline of benign noise (logons, browsing, routine Kerberos traffic) and injects 5 attack scenarios at random points, writing everything to `logs/events.jsonl` in chronological order.
- **`rules/*.yml`** — Sigma-style metadata (title, MITRE ID, tactic, severity, description) for each detection, kept separate from logic so rules stay readable and easy to extend.
- **`rules.py`** — loads each YAML rule and pairs it with a small detection function (windowing, thresholding, pattern matching) that scans the event stream.
- **`detector.py`** — runs every rule against the full event stream, sorts alerts by severity, and writes `alerts.json`.

## Techniques simulated & detected

| MITRE ATT&CK ID | Technique | Tactic | Detection Logic |
|---|---|---|---|
| T1110.001 | Password Guessing (Brute Force) | Credential Access | ≥5 failed logons (4625) from one account+IP within 2 min, followed by a success (4624) within 5 min |
| T1558.003 | Kerberoasting | Credential Access | ≥3 distinct SPNs requested via RC4-encrypted TGS (4769, encryption type `0x17`) by one account within 60s |
| T1059.001 | Encoded PowerShell Command | Execution | PowerShell process (Sysmon EID 1) launched with `-enc` / `-EncodedCommand` |
| T1046 | Network Service Discovery (Port Scan) | Discovery | One source IP connecting (Sysmon EID 3) to ≥15 distinct ports within 10s |
| T1003.001 | LSASS Memory Access (Credential Dumping) | Credential Access | Non-allowlisted process granted high-privilege access (Sysmon EID 10) to `lsass.exe` |

## Running it

No external dependencies required — pure Python 3 standard library. (PyYAML is used automatically if installed, with a built-in fallback parser if it isn't.)

```bash
git clone https://github.com/<your-username>/attacksim-detect.git
cd attacksim-detect
python3 simulator.py   # generates logs/events.jsonl
python3 detector.py    # analyzes the log and prints/saves alerts
```

## Sample output

```
Loaded 381 events for analysis...

5 ALERT(S) TRIGGERED
============================================================
[CRITICAL] Suspicious Access to LSASS Process  (T1003.001 - Credential Access)
           GrantedAccess=0x1410 to lsass.exe from C:\Users\Public\update.exe
------------------------------------------------------------
[  HIGH  ] Successful Login Following Brute Force Attempts  (T1110.001 - Credential Access)
           7 failed logons then a success at 2026-08-20T09:12:52+00:00
------------------------------------------------------------
[  HIGH  ] Possible Kerberoasting via RC4 TGS Requests  (T1558.003 - Credential Access)
           3 distinct RC4 TGS requests within 60s: ['CIFS/fs01.corp.local', 'HTTP/app02.corp.local', 'MSSQLSvc/db01.corp.local']
------------------------------------------------------------
[ MEDIUM ] Suspicious Encoded PowerShell Execution  (T1059.001 - Execution)
           Encoded command line: powershell.exe -NoP -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA...
------------------------------------------------------------
[ MEDIUM ] Network Service Discovery (Port Scan)  (T1046 - Discovery)
           15 distinct destination ports within 10s: [21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389]
------------------------------------------------------------

Saved 5 alerts -> alerts.json
```

All 5 injected techniques are detected against 381 total events (376 of them benign noise) with zero false positives in this run.

## Possible extensions

- Port rules to real [Sigma](https://github.com/SigmaHQ/sigma) format and run them through `pySigma` for compatibility with actual SIEM backends
- Forward `events.jsonl` into Splunk or Wazuh instead of a flat file, to test the same rules as real SPL/Wazuh detections
- Add a scoring/triage layer that correlates multiple alerts into a single incident (e.g., brute force → Kerberoasting → LSASS access as one attack chain)
- Add unit tests for each detection function using pytest

## License

MIT — see [LICENSE](LICENSE).
