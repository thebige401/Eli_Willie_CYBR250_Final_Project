# ForensicKit

**Digital Artifact Collector for Live Systems & Mounted Disk Images**

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](#requirements)
[![Platform: Linux · Windows · macOS](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](#requirements)
[![Tests: 79 passed](https://img.shields.io/badge/tests-79%20passed-brightgreen)](#running-the-test-suite)

**Author:** Eli Willie  
**Course Final Project**

---

## Table of Contents

1. [Overview](#overview)
2. [What It Collects](#what-it-collects)
3. [Output Files](#output-files)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Quick Start](#quick-start)
7. [Usage Reference](#usage-reference)
8. [Running Against a Mounted Image](#running-against-a-mounted-image)
9. [Running the Test Suite](#running-the-test-suite)
10. [Output Screenshots](#output-screenshots)
11. [Project Layout](#project-layout)
12. [Forensic Methodology Notes](#forensic-methodology-notes)
13. [Limitations & Caveats](#limitations--caveats)
14. [Troubleshooting](#troubleshooting)
15. [License](#license)

---

## Overview

ForensicKit is my final project — a single-file Python forensic triage tool that collects digital evidence from a live running system or a mounted disk image and produces three output artifacts:

| Output | Purpose |
|---|---|
| `<CASE>_evidence.json` | Machine-readable structured evidence |
| `<CASE>_report.html` | Human-readable interactive report (dark-themed) |
| `<CASE>_manifest.txt` | SHA-256 integrity manifest of both output files |

The goal was to build something that could realistically be used in an incident response or forensics scenario — you run one script, and you walk away with a structured evidence package you can hand off or analyze later.

It is intentionally self-contained: one Python source file, one optional third-party dependency (`psutil`), no databases, no servers, no install step beyond cloning the repo.

---

## What It Collects

| Category | Artifact | Source |
|---|---|---|
| **System** | OS, kernel, hostname, boot time, memory | `platform`, `psutil`, `uname` |
| **Processes** | PID, name, user, cmdline, exe path, open connections | `psutil` / `ps` / `tasklist` |
| **Network** | Active TCP/UDP connections, bound ports, NIC addresses | `psutil` / `ss` / `netstat` |
| **DNS / Hosts** | `/etc/hosts`, DNS cache (Windows), resolvectl stats | OS filesystem / `ipconfig` |
| **Users** | Local accounts, last logins, currently logged-in sessions | `/etc/passwd`, `last`, `who`, `net user` |
| **Persistence** | Cron jobs, systemd timers, startup registry keys, init.d | `/etc/cron*`, `schtasks`, registry |
| **Startup** | Autorun entries, rc.local, systemd enabled units | `systemctl`, registry run keys |
| **Filesystem** | Files modified in the last N hours (configurable) | `os.walk` with `mtime` filter |
| **Logs** | syslog, auth.log, kern.log, journalctl warnings, Event Log | `/var/log/*`, `wevtutil` |
| **Open Handles** | Files currently held open by processes | `lsof` / `handle.exe` |

---

## Output Files

### `<CASE>_evidence.json`

Structured JSON with every artifact set. Schema:

```json
{
  "case_id": "CASE-20260530-120000",
  "generated": "2026-05-30T12:00:00Z",
  "collector": "ForensicKit 1.0.0",
  "host": "hostname",
  "evidence": [
    {
      "category": "System",
      "title": "System Information",
      "source": "OS APIs / uname / systeminfo",
      "timestamp": "2026-05-30T12:00:00Z",
      "data": { },
      "raw": ""
    }
  ]
}
```

### `<CASE>_report.html`

Self-contained HTML file with a fixed dark sidebar navigation, collapsible sections, key-value grids, data tables, and scrollable pre-formatted output. Open in any modern browser — no internet connection required.

### `<CASE>_manifest.txt`

```
# ForensicKit SHA-256 Manifest
# Case: CASE-20260530-120000
# Generated: 2026-05-30T12:00:00Z

6e81f2f4...  CASE-20260530-120000_evidence.json
32f62bac...  CASE-20260530-120000_report.html
```

Use this to verify evidence integrity:

```bash
# Linux / macOS
sha256sum -c CASE-20260530-120000_manifest.txt

# Windows (PowerShell)
Get-Content CASE-20260530-120000_manifest.txt |
  Where-Object { $_ -match '^[0-9a-f]{64}' } |
  ForEach-Object {
    $hash, $file = $_ -split '  '
    $actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
    if ($actual -eq $hash) { "OK: $file" } else { "MISMATCH: $file" }
  }
```

---

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.8 or newer |
| `psutil` *(recommended)* | any recent version |
| `pytest` *(tests only)* | any recent version |

No other dependencies. All core functionality uses standard library modules (`os`, `subprocess`, `socket`, `hashlib`, `json`, `platform`, `pathlib`, etc.).

`psutil` is not strictly required, but I would recommend installing it. Without it, ForensicKit falls back to calling `ps`, `tasklist`, `netstat`, and `ss` directly, which gives you less detail and can be slower.

---

## Installation

### 1 — Clone or download

```bash
git clone https://github.com/thebige401/Eli_Willie_CYBR250_Final_Project.git forensickit
cd forensickit
```

Or just download `forensic_collector.py` as a standalone file if you don't need the full repo.

### 2 — Install the optional dependency

```bash
pip install psutil
```

On systems that enforce PEP 668 (Debian 12+, Ubuntu 24+):

```bash
pip install psutil --break-system-packages
# or use a virtual environment:
python -m venv .venv && source .venv/bin/activate && pip install psutil
```

### 3 — (Tests only) Install pytest

```bash
pip install pytest
# or
pip install pytest --break-system-packages
```

---

## Quick Start

```bash
# Live system — minimal invocation
python forensic_collector.py

# Live system — verbose output, custom output folder
python forensic_collector.py -v -o /tmp/evidence

# Live system — custom case ID, look back 48 hours for recent files
python forensic_collector.py --case-id INC-2026-001 -r 48 -v

# Mounted disk image at /mnt/disk1
python forensic_collector.py -t /mnt/disk1 -o /tmp/case002 -v

# JSON only (skip HTML report and manifest)
python forensic_collector.py --no-html --no-hash
```

After a successful run you will see output like this:

```
============================================================
  ForensicKit v1.0.0 — Digital Artifact Collector
============================================================
[*] Target root  : /
[*] Output dir   : reports
[*] Recent files : last 24h
[*] Collecting artifacts ...
[12:00:01] Collecting system information ...
[12:00:01] Collecting running processes ...
[12:00:01] Collecting network connections ...
[12:00:01] Collecting DNS / hosts information ...
[12:00:01] Collecting user accounts ...
[12:00:01] Collecting scheduled tasks / cron ...
[12:00:01] Collecting startup / autorun items ...
[12:00:01] Collecting files modified in last 24h under / ...
[12:00:03] Collecting log excerpts ...
[12:00:03] Collecting open file handles ...
[+] Collected 10 artifact sets.
[*] Writing JSON evidence file ...
    -> reports/CASE-20260530-120000_evidence.json
[*] Writing HTML report ...
    -> reports/CASE-20260530-120000_report.html
[*] Writing SHA-256 manifest ...
    -> reports/CASE-20260530-120000_manifest.txt
[+] Done.
```

Then open the HTML report in your browser:

```bash
# Linux
xdg-open reports/CASE-*_report.html

# macOS
open reports/CASE-*_report.html

# Windows
start reports\CASE-*_report.html
```

---

## Usage Reference

```
usage: forensic_collector.py [-h] [-t TARGET] [-o OUTPUT] [--case-id CASE_ID]
                              [-r RECENT_HOURS] [-v] [--no-html] [--no-hash]

options:
  -h, --help            show this help message and exit
  -t TARGET             target root directory (default: /)
  -o OUTPUT             output directory (default: reports)
  --case-id CASE_ID     custom case ID (default: auto-generated timestamp)
  -r RECENT_HOURS       hours to look back for recently modified files (default: 24)
  -v, --verbose         print progress to stdout
  --no-html             skip HTML report generation
  --no-hash             skip SHA-256 manifest generation
```

---

## Running Against a Mounted Image

ForensicKit supports pointing at a mounted disk image instead of the live system root. This is useful when you have an image mounted at `/mnt/evidence` and want to pull filesystem artifacts from it without touching the live OS.

```bash
# Mount the image first (Linux example)
sudo mount -o ro,loop disk.img /mnt/evidence

# Run ForensicKit against the image
python forensic_collector.py -t /mnt/evidence -o /tmp/case003 -v
```

**Important:** Process and network collectors always read from the live OS, not the image. That is by design — you cannot recover live process state from a disk image. Everything filesystem-based (hosts file, cron, logs, passwd, recent files) will correctly pull from the mounted image path.

---

## Running the Test Suite

The project includes 79 tests covering every major component. To run them you will need `pytest`:

```bash
pip install pytest
```

### Run all 79 tests

```bash
cd forensickit                               # repo root
python -m pytest tests/test_forensic_collector.py -v
```

Expected output (abridged):

```
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.0.3
collected 79 items

tests/test_forensic_collector.py::TestMakeEvidence::test_category_and_title PASSED
tests/test_forensic_collector.py::TestMakeEvidence::test_required_keys_present PASSED
...
tests/test_forensic_collector.py::TestMainFunction::test_main_creates_output_files PASSED
tests/test_forensic_collector.py::TestEdgeCases::test_html_xss_escape PASSED
...
========================= 79 passed in 5.6s ===================================
```

### Test categories

| Class | What it tests |
|---|---|
| `TestMakeEvidence` | Evidence factory — keys, types, timestamp format |
| `TestSha256String` | SHA-256 helper — known hash, hex chars, empty string |
| `TestSha256File` | File hashing — known content, missing file, empty file |
| `TestReadFile` | File reader — truncation, missing file, binary content |
| `TestRun` | Subprocess wrapper — success, missing command, timeout, non-zero exit |
| `TestCollectorInit` | Constructor defaults and custom params |
| `TestCollectorSystemInfo` | Category, fields, hostname present |
| `TestCollectorProcesses` | Category, list type, at least one process |
| `TestCollectorNetwork` | Category, connections key present |
| `TestCollectorDns` | hosts_file key present |
| `TestCollectorUsers` | Category, data collected |
| `TestCollectorScheduledTasks` | Category Persistence |
| `TestCollectorStartupItems` | Category Persistence |
| `TestCollectorRecentFiles` | Finds new file; excludes old file; count == len(files); limit 1000 |
| `TestCollectorLogs` | Category Logs, data is dict |
| `TestCollectorOpenHandles` | raw_output key present |
| `TestRunAll` | Returns list; all 7 categories present; survives broken collector |
| `TestReportGeneratorJson` | File created; valid JSON; case_id in filename; evidence count |
| `TestReportGeneratorHtml` | File created; DOCTYPE; case_id; category names; XSS escape |
| `TestReportGeneratorManifest` | File created; contains SHA-256 lines; self-exclusion |
| `TestCliParser` | All flags — defaults, custom values, boolean flags |
| `TestMainFunction` | End-to-end: return code 0; JSON + HTML + manifest created; --no-html; --no-hash |
| `TestEdgeCases` | render_data types; empty table; row limit; HTML escaping; auto case_id |

### Run a single test class

```bash
python -m pytest tests/test_forensic_collector.py::TestCollectorRecentFiles -v
```

### Run without pytest (stdlib only)

```bash
python tests/test_forensic_collector.py
```

---

## Output Screenshots

### Terminal — verbose run

```
============================================================
  ForensicKit v1.0.0 — Digital Artifact Collector
============================================================
[*] Target root  : /
[*] Output dir   : reports
[*] Recent files : last 2h
[*] Collecting artifacts ...
[01:21:14] Collecting system information ...
[01:21:14] Collecting running processes ...
[01:21:14] Collecting network connections ...
[01:21:14] Collecting DNS / hosts information ...
[01:21:14] Collecting user accounts ...
[01:21:14] Collecting scheduled tasks / cron ...
[01:21:14] Collecting startup / autorun items ...
[01:21:14] Collecting files modified in last 2h under / ...
[01:21:16] Collecting log excerpts ...
[01:21:16] Collecting open file handles ...
[+] Collected 10 artifact sets.
[*] Writing JSON evidence file ...
    -> reports/DEMO-2026_evidence.json
[*] Writing HTML report ...
    -> reports/DEMO-2026_report.html
[*] Writing SHA-256 manifest ...
    -> reports/DEMO-2026_manifest.txt
[+] Done.
```

### SHA-256 Manifest

```
# ForensicKit SHA-256 Manifest
# Case: DEMO-2026
# Generated: 2026-05-31T01:21:16Z

6e81f2f4e2c23f2ad5ab8eb328d0cb57dbae764e83dcfd520196fd2836f1f2b7  DEMO-2026_evidence.json
32f62bac9ede4df604140eeb2fd411f6e4fdb3753626e39de57a591af33ee8c0  DEMO-2026_report.html
```

### HTML Report — sidebar navigation

The dark-themed HTML report opens in any browser with no internet connection. The left sidebar has jump-links to each evidence category: **System, Processes, Network, Users, Persistence, Filesystem, Logs**

Each card shows:
- Card header: artifact title + source + timestamp
- Key-value grids for flat data (system info, interface addresses)
- Sortable tables for list data (processes, connections, recent files)
- Scrollable `<pre>` blocks for raw log output
- Collapsible `<details>` trees for nested structures

### Test suite output

```
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.0.3
collected 79 items

tests/test_forensic_collector.py::TestMakeEvidence::test_category_and_title PASSED [  1%]
...
tests/test_forensic_collector.py::TestMainFunction::test_main_runs_successfully PASSED [ 87%]
...
tests/test_forensic_collector.py::TestEdgeCases::test_report_auto_case_id PASSED [100%]

========================= 79 passed in 5.6s ===================================
```

---

## Project Layout

```
forensickit/
+-- forensic_collector.py   # Main script — collector + report generator + CLI
+-- README.md               # This file
+-- reports/                # Default output directory (git-ignored)
|   +-- <CASE>_evidence.json
|   +-- <CASE>_report.html
|   +-- <CASE>_manifest.txt
+-- tests/
    +-- test_forensic_collector.py   # 79-test suite
```

---

## Forensic Methodology Notes

### Evidence integrity

SHA-256 hashes are computed after writing each output file and recorded in the manifest. You should always keep the manifest alongside the evidence files so the integrity of the collection can be verified later — whether that is for a class demo, a peer review, or an actual investigation.

### Volatility ordering

ForensicKit collects in order of volatility (most volatile first), following RFC 3227 / NIST SP 800-86 guidance:

1. Running processes (RAM state)
2. Network connections (ephemeral)
3. DNS cache / ARP (short-lived)
4. User sessions
5. Persistent configuration (cron, startup)
6. Filesystem (recent files, logs)

### Live vs. image mode

| Artifact | Live system | Mounted image |
|---|---|---|
| Processes | Yes, from OS | Live OS only |
| Network connections | Yes, from OS | Live OS only |
| Hosts / passwd / cron / logs | Yes, -t / | Yes, -t /mnt/image |
| Recent files | Yes, -t / | Yes, -t /mnt/image |

### Privilege

- **Linux/macOS:** Run as `root` (or `sudo`) for a complete process list, shadow file access, and full `lsof` output. ForensicKit will partially succeed as a non-root user but will miss privileged processes and some log files.
- **Windows:** Run from an elevated command prompt (Run as Administrator).

---

## Limitations & Caveats

- **Not a forensic imaging tool.** ForensicKit does not create bit-for-bit disk images. Use `dd`, `dcfldd`, FTK Imager, or `ewfacquire` for that.
- **Recent-files walk limit.** The collector stops at 1,000 files matching the time window. You can increase this constant in the source if you need more.
- **Windows Event Log.** Requires `wevtutil`, which is present on all modern Windows systems. It reads the last 50 events per log by default.
- **Mounted image mode.** Process and network collectors always use the live running OS, not the image. This is intentional.
- **macOS support.** Most Linux collectors work on macOS, but some (journalctl, `/etc/shadow`, systemd) are absent. The unified log collector falls back to `log show`.
- **Anti-forensics.** A sophisticated attacker may have already modified timestamps, hidden processes, or tampered with logs before this tool runs. ForensicKit cannot detect that on its own.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `psutil not installed` warning | psutil missing | `pip install psutil` |
| Empty process list | Permission denied | Run as root / Administrator |
| `lsof error` in open-handles section | lsof not installed | `apt-get install lsof` |
| Recent-files takes > 30 s | Large filesystem | Use `-t` to point at a specific subtree |
| HTML report shows blank sections | Collector failed silently | Re-run with `-v` to see warnings |
| Permission denied on shadow | Non-root user | `sudo python forensic_collector.py` |
| `Command not found: schtasks` (Linux) | Running on Linux | Normal — Windows-only collector is skipped |
| Manifest SHA-256 mismatch | File was modified after collection | Evidence tampering possible — investigate |
| `UnicodeEncodeError` writing HTML (Windows) | Default cp1252 encoding | Open the output file with `encoding="utf-8"` |

---

## License

MIT — do whatever you like, just preserve the copyright header in the source.

```
Copyright (c) 2026 Eli Willie

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software ... (standard MIT text)
```

---

*ForensicKit is provided for lawful digital forensic investigation and educational purposes. Always obtain proper legal authority before collecting evidence from any system you don't own.*
