#!/usr/bin/env python3
"""
================================================================================
ForensicKit - Live System & Mounted Image Forensic Artifact Collector
================================================================================
Author      : Eli Willie
Course      : CYBR 250 - Final Project
Date        : May 30, 2026
Version     : 1.0.0
Python      : 3.8+
Platforms   : Windows, Linux, macOS (partial)
License     : MIT

Description
-----------
This is my final project for CYBR 250. ForensicKit is a single-file forensic
triage tool that collects digital evidence from either a live running system or
a mounted disk image. The idea is to give an investigator a quick snapshot of
what was happening on a machine — processes, connections, recent file changes,
logs — all in one pass, without needing to install anything complicated.

Output is a structured JSON evidence file, an interactive HTML report you can
open in any browser, and a SHA-256 manifest so you can verify the files
weren't tampered with after collection.

Artifacts collected
-------------------
  * System information    - hostname, OS, kernel, timezone, boot time
  * Running processes     - PID, name, user, cmdline, open files, network
  * Network connections   - active TCP/UDP connections with remote endpoints
  * Listening services    - bound ports and the processes that own them
  * DNS cache / hosts     - /etc/hosts (Linux) or ipconfig /displaydns (Win)
  * User accounts         - local users, last login times (Linux: /etc/passwd)
  * Scheduled tasks / cron- crontabs (Linux), schtasks (Windows)
  * Startup items         - autorun registry keys (Win) / init/systemd units
  * Recent files          - files modified in the last N hours (configurable)
  * Log excerpts          - syslog / Windows Event Log (last 200 lines/events)
  * Open file handles     - files currently held open by processes (Linux lsof)
  * Hash manifest         - SHA-256 of every collected artifact file

Usage
-----
  python forensic_collector.py [OPTIONS]

  -o, --output  DIR    Output directory for the report  [default: ./reports]
  -t, --target  PATH   Root path of a mounted image     [default: / (live)]
  -r, --recent  HOURS  Look-back window for recent files [default: 24]
  -v, --verbose        Print progress to stdout
  --no-html            Skip HTML report (JSON only)
  --no-hash            Skip SHA-256 manifest

Examples
--------
  # Live system, default output
  python forensic_collector.py -v

  # Mounted image at /mnt/evidence
  python forensic_collector.py -t /mnt/evidence -o /tmp/case001

  # Only last 48 hours of recent files, verbose
  python forensic_collector.py -r 48 -v

================================================================================
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# psutil gives us much richer process and network data than shell commands do.
# It's not strictly required — the tool falls back to ps/tasklist/netstat —
# but the output is noticeably better with it installed (pip install psutil).
# ---------------------------------------------------------------------------
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ---------------------------------------------------------------------------
# Detect which OS we're running on so collectors can branch appropriately.
# Most collectors have separate Linux, Windows, and macOS code paths.
# ---------------------------------------------------------------------------
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"


# ============================================================================
# Evidence item factory
# Each artifact collected by the tool gets wrapped in this standard structure
# so the report generator always has a consistent format to work with.
# ============================================================================

def make_evidence(category: str, title: str, data: Any,
                  source: str = "", raw: str = "") -> Dict:
    """
    Build a standardized evidence dictionary for a single collected artifact.

    Every collector calls this so the report generator always gets the same
    keys regardless of what the data actually contains.
    """
    return {
        "category": category,
        "title":    title,
        "source":   source,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "data":     data,
        "raw":      raw,
    }


# ============================================================================
# Low-level helpers
# These are small utility functions used throughout the collectors.
# Keeping them separate makes the collector methods easier to read and test.
# ============================================================================

def _run(cmd: List[str], timeout: int = 30) -> Tuple[str, str, int]:
    """
    Run a shell command and return (stdout, stderr, return_code).

    Using a helper here instead of calling subprocess directly everywhere
    means we handle timeouts and missing commands in one place rather than
    repeating try/except blocks in every collector.
    """
    try:
        completed_process = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return completed_process.stdout, completed_process.stderr, completed_process.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s: {' '.join(cmd)}", 124
    except Exception as exc:  # noqa: BLE001
        return "", str(exc), 1


def _read_file(path: str, max_lines: int = 500) -> str:
    """
    Safely read a text file and return up to max_lines lines from the end.

    Reading from the tail of the file is useful for logs where the most
    recent entries are what we care about. Errors come back as a descriptive
    string rather than raising, so a permission error on one file doesn't
    crash the whole collection run.
    """
    try:
        with open(path, "r", errors="replace") as file_handle:
            all_lines = file_handle.readlines()
        return "".join(all_lines[-max_lines:])
    except (PermissionError, FileNotFoundError, OSError) as exc:
        return f"[Could not read {path}: {exc}]"


def _sha256_file(path: str) -> Optional[str]:
    """
    Compute the SHA-256 hex digest of a file on disk.

    Reads in 64KB chunks so large files don't blow out memory.
    Returns None if the file can't be read (e.g. permission denied).
    This is used by the manifest writer to fingerprint each output file.
    """
    sha256_hasher = hashlib.sha256()
    try:
        with open(path, "rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(65536), b""):
                sha256_hasher.update(chunk)
        return sha256_hasher.hexdigest()
    except OSError:
        return None


def _sha256_string(input_string: str) -> str:
    """Hash a plain string — used in tests to verify the hasher works correctly."""
    return hashlib.sha256(input_string.encode()).hexdigest()


# ============================================================================
# Collectors
# ============================================================================

class ForensicCollector:
    """
    The main collector class. Each public method gathers one category of
    forensic artifacts and appends the result to self.evidence.

    I structured it this way so each collector is independently testable —
    you can call collect_processes() on its own without running everything.
    run_all() just calls them all in volatility order (most ephemeral first,
    following RFC 3227 guidance).

    Parameters
    ----------
    target_root : str
        Root path to inspect. Use "/" for a live system or "/mnt/evidence"
        for a mounted disk image. Note: process and network collectors always
        read from the live OS regardless of this setting — you can't get
        running process state from a disk image.
    recent_hours : int
        How many hours back to search for recently modified files.
    verbose : bool
        Print timestamped progress messages to stdout.
    """

    def __init__(self, target_root: str = "/",
                 recent_hours: int = 24,
                 verbose: bool = False):
        self.target_root  = Path(target_root)
        self.recent_hours = recent_hours
        self.verbose      = verbose
        self.evidence: List[Dict] = []
        self._collection_start_time = datetime.datetime.now(datetime.timezone.utc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(self, message: str) -> None:
        """Print a timestamped progress message if verbose mode is on."""
        if self.verbose:
            timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")

    def _add_evidence(self, evidence_item: Dict) -> None:
        """Append a finished evidence item to the collection list."""
        self.evidence.append(evidence_item)

    # ------------------------------------------------------------------
    # 1. System information
    # ------------------------------------------------------------------

    def collect_system_info(self) -> None:
        """
        Collect basic OS and hardware identifiers.

        This is always the first thing collected — it gives context for
        everything else in the report (what machine, what OS, when collected).
        """
        self._log("Collecting system information ...")
        system_info: Dict[str, Any] = {
            "hostname":      socket.gethostname(),
            "fqdn":          socket.getfqdn(),
            "platform":      platform.platform(),
            "system":        platform.system(),
            "release":       platform.release(),
            "version":       platform.version(),
            "machine":       platform.machine(),
            "processor":     platform.processor(),
            "python_version": platform.python_version(),
            "collection_time": self._collection_start_time.isoformat(),
        }

        # psutil gives us boot time and memory stats if available
        if HAS_PSUTIL:
            try:
                system_info["boot_time"] = datetime.datetime.fromtimestamp(
                    psutil.boot_time()).isoformat()
                system_info["cpu_count_logical"]  = psutil.cpu_count()
                system_info["cpu_count_physical"] = psutil.cpu_count(logical=False)
                virtual_memory = psutil.virtual_memory()
                system_info["memory_total_gb"] = round(virtual_memory.total / (1024**3), 2)
                system_info["memory_used_pct"] = virtual_memory.percent
            except Exception:  # noqa: BLE001
                pass

        # Platform-specific extras — uname on Linux, systeminfo on Windows
        if IS_LINUX:
            uname_output, _, _ = _run(["uname", "-a"])
            system_info["uname"] = uname_output.strip()
            system_info["timezone"] = _run(["cat", "/etc/timezone"])[0].strip()
            system_info["os_release"] = _read_file("/etc/os-release", max_lines=50)
        elif IS_WINDOWS:
            systeminfo_output, _, _ = _run(["systeminfo"])
            system_info["systeminfo"] = systeminfo_output[:4000]

        self._add_evidence(make_evidence(
            category="System",
            title="System Information",
            data=system_info,
            source="OS APIs / uname / systeminfo",
        ))

    # ------------------------------------------------------------------
    # 2. Running processes
    # ------------------------------------------------------------------

    def collect_processes(self) -> None:
        """
        Collect the running process list with as much detail as possible.

        With psutil we get structured per-process data including open network
        connections. Without it we fall back to ps/tasklist and store the raw
        text output instead — less useful but better than nothing.
        """
        self._log("Collecting running processes ...")
        process_list: List[Dict] = []

        if HAS_PSUTIL:
            process_attributes = ["pid", "name", "username", "status",
                     "create_time", "cmdline", "exe",
                     "cpu_percent", "memory_percent"]
            for process in psutil.process_iter(attrs=process_attributes, ad_value=None):
                process_info = process.info
                # Convert epoch timestamp to ISO format for readability
                if process_info.get("create_time"):
                    process_info["create_time"] = datetime.datetime.fromtimestamp(
                        process_info["create_time"]).isoformat()
                if process_info.get("cmdline"):
                    process_info["cmdline"] = " ".join(process_info["cmdline"])
                # Grab per-process network connections — useful for spotting
                # processes with unexpected outbound connections
                try:
                    open_connections = process.net_connections()
                    process_info["connections"] = [
                        {
                            "fd":     conn.fd,
                            "type":  str(conn.type),
                            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                            "status": conn.status,
                        }
                        for conn in open_connections
                    ]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    # Process may have exited or we don't have permission — skip connections
                    process_info["connections"] = []
                process_list.append(process_info)
        else:
            # Fallback: run ps or tasklist and store raw text
            if IS_WINDOWS:
                raw_output, _, _ = _run(["tasklist", "/FO", "CSV", "/V"])
            else:
                raw_output, _, _ = _run(["ps", "auxww"])
            process_list = [{"raw_output": raw_output}]

        self._add_evidence(make_evidence(
            category="Processes",
            title="Running Processes",
            data=process_list,
            source="psutil / ps / tasklist",
        ))

    # ------------------------------------------------------------------
    # 3. Network connections
    # ------------------------------------------------------------------

    def collect_network(self) -> None:
        """
        Collect active TCP/UDP connections and network interface addresses.

        Active connections are one of the most useful things to capture early —
        they're ephemeral and tell you what the machine was talking to at the
        moment of collection.
        """
        self._log("Collecting network connections ...")
        active_connections: List[Dict] = []

        if HAS_PSUTIL:
            try:
                for connection in psutil.net_connections(kind="inet"):
                    active_connections.append({
                        "fd":      connection.fd,
                        "family":  str(connection.family),
                        "type":   str(connection.type),
                        "laddr":  f"{connection.laddr.ip}:{connection.laddr.port}" if connection.laddr else "",
                        "raddr":  f"{connection.raddr.ip}:{connection.raddr.port}" if connection.raddr else "",
                        "status": connection.status,
                        "pid":    connection.pid,
                    })
            except psutil.AccessDenied as exc:
                active_connections = [{"error": str(exc)}]
        else:
            # Fall back to netstat / ss if psutil isn't available
            if IS_WINDOWS:
                raw_output, _, _ = _run(["netstat", "-ano"])
            else:
                raw_output, _, _ = _run(["ss", "-tunap"])
                if not raw_output:
                    raw_output, _, _ = _run(["netstat", "-tunap"])
            active_connections = [{"raw_output": raw_output}]

        # Network interface addresses — useful for correlating with connections
        network_interfaces: Dict = {}
        if HAS_PSUTIL:
            try:
                for interface_name, interface_addresses in psutil.net_if_addrs().items():
                    network_interfaces[interface_name] = [
                        {"family": str(addr.family), "address": addr.address,
                         "netmask": addr.netmask, "broadcast": addr.broadcast}
                        for addr in interface_addresses
                    ]
            except Exception:  # noqa: BLE001
                pass

        self._add_evidence(make_evidence(
            category="Network",
            title="Active Network Connections",
            data={"connections": active_connections, "interfaces": network_interfaces},
            source="psutil / ss / netstat",
        ))

    # ------------------------------------------------------------------
    # 4. DNS cache / hosts file
    # ------------------------------------------------------------------

    def collect_dns(self) -> None:
        """
        Collect the hosts file and (on Windows) the DNS client cache.

        Malware and attackers sometimes add entries to /etc/hosts to redirect
        traffic, so this is worth capturing. The DNS cache shows what domains
        the machine was looking up recently.
        """
        self._log("Collecting DNS / hosts information ...")
        dns_data: Dict[str, Any] = {}

        # Hosts file path differs between Windows and Unix-like systems
        hosts_file_path = self.target_root / "etc" / "hosts"
        if IS_WINDOWS:
            hosts_file_path = Path(
                os.environ.get("SystemRoot", r"C:\Windows")
            ) / "System32" / "drivers" / "etc" / "hosts"

        dns_data["hosts_file"] = _read_file(str(hosts_file_path))

        if IS_WINDOWS:
            dns_cache_output, _, _ = _run(["ipconfig", "/displaydns"])
            dns_data["dns_cache"] = dns_cache_output[:8000]
        elif IS_LINUX:
            # resolvectl gives us resolver stats on systemd-based systems
            resolvectl_output, _, _ = _run(["resolvectl", "statistics"])
            dns_data["resolvectl_stats"] = resolvectl_output.strip()

        self._add_evidence(make_evidence(
            category="Network",
            title="DNS Cache / Hosts File",
            data=dns_data,
            source=str(hosts_file_path),
        ))

    # ------------------------------------------------------------------
    # 5. User accounts
    # ------------------------------------------------------------------

    def collect_users(self) -> None:
        """
        Collect local user account info and active login sessions.

        Knowing what accounts exist and who was logged in at collection time
        is important context for any investigation. On Linux we also check
        whether the shadow file is readable (it shouldn't be as a non-root user).
        """
        self._log("Collecting user accounts ...")
        user_data: Dict[str, Any] = {}

        if IS_LINUX or IS_MAC:
            passwd_file_path = self.target_root / "etc" / "passwd"
            user_data["passwd"] = _read_file(str(passwd_file_path))
            shadow_file_path = self.target_root / "etc" / "shadow"
            user_data["shadow_accessible"] = shadow_file_path.exists()

            # Last 30 logins
            last_logins_output, _, _ = _run(["last", "-n", "30"])
            user_data["last_logins"] = last_logins_output

            # Who is currently logged in
            logged_in_output, _, _ = _run(["who"])
            user_data["currently_logged_in"] = logged_in_output

        elif IS_WINDOWS:
            net_user_output, _, _ = _run(["net", "user"])
            user_data["net_user"] = net_user_output
            local_admins_output, _, _ = _run(["net", "localgroup", "administrators"])
            user_data["local_admins"] = local_admins_output

        # psutil can also give us logged-in users cross-platform
        if HAS_PSUTIL:
            try:
                logged_in_users = []
                for user_session in psutil.users():
                    logged_in_users.append({
                        "name":     user_session.name,
                        "terminal": user_session.terminal,
                        "host":     user_session.host,
                        "started":  datetime.datetime.fromtimestamp(user_session.started).isoformat(),
                    })
                user_data["logged_in_psutil"] = logged_in_users
            except Exception:  # noqa: BLE001
                pass

        self._add_evidence(make_evidence(
            category="Users",
            title="User Accounts & Sessions",
            data=user_data,
            source="/etc/passwd / net user",
        ))

    # ------------------------------------------------------------------
    # 6. Scheduled tasks / cron
    # ------------------------------------------------------------------

    def collect_scheduled_tasks(self) -> None:
        """
        Collect cron jobs (Linux/macOS) or scheduled tasks (Windows).

        Persistence via scheduled tasks is one of the most common techniques
        attackers use to survive reboots, so this is a key thing to document.
        """
        self._log("Collecting scheduled tasks / cron ...")
        scheduled_task_data: Dict[str, Any] = {}

        if IS_LINUX or IS_MAC:
            # Check all the standard cron locations
            cron_locations = [
                "/etc/crontab",
                "/etc/cron.d",
                "/etc/cron.daily",
                "/etc/cron.hourly",
                "/etc/cron.weekly",
                "/etc/cron.monthly",
            ]
            for cron_path in cron_locations:
                full_cron_path = self.target_root / cron_path.lstrip("/")
                if full_cron_path.is_file():
                    scheduled_task_data[cron_path] = _read_file(str(full_cron_path))
                elif full_cron_path.is_dir():
                    cron_dir_entries = {}
                    for cron_file in sorted(full_cron_path.iterdir()):
                        if cron_file.is_file():
                            cron_dir_entries[cron_file.name] = _read_file(str(cron_file))
                    scheduled_task_data[cron_path] = cron_dir_entries

            # Current user's crontab — only makes sense on a live system
            if str(self.target_root) in ("/", ""):
                current_crontab_output, _, _ = _run(["crontab", "-l"])
                scheduled_task_data["current_user_crontab"] = current_crontab_output or "(empty)"

            # systemd timers are basically the modern equivalent of cron
            systemd_timers_output, _, _ = _run(["systemctl", "list-timers", "--all", "--no-pager"])
            scheduled_task_data["systemd_timers"] = systemd_timers_output

        elif IS_WINDOWS:
            schtasks_output, _, _ = _run(["schtasks", "/query", "/FO", "CSV", "/V"],
                             timeout=60)
            scheduled_task_data["scheduled_tasks"] = schtasks_output[:8000]

        self._add_evidence(make_evidence(
            category="Persistence",
            title="Scheduled Tasks / Cron Jobs",
            data=scheduled_task_data,
            source="/etc/crontab / schtasks",
        ))

    # ------------------------------------------------------------------
    # 7. Startup / autorun items
    # ------------------------------------------------------------------

    def collect_startup_items(self) -> None:
        """
        Collect autorun and startup entries.

        Along with scheduled tasks, startup items are the other main way
        malware establishes persistence. On Windows that means registry Run
        keys; on Linux it's systemd enabled units, init.d scripts, and rc.local.
        """
        self._log("Collecting startup / autorun items ...")
        startup_data: Dict[str, Any] = {}

        if IS_LINUX or IS_MAC:
            # systemd enabled units — what starts at boot
            systemd_enabled_output, _, _ = _run(
                ["systemctl", "list-unit-files", "--state=enabled", "--no-pager"]
            )
            startup_data["systemd_enabled"] = systemd_enabled_output

            # Legacy init.d scripts
            init_d_path = self.target_root / "etc" / "init.d"
            if init_d_path.is_dir():
                startup_data["init_d_scripts"] = [
                    script_file.name for script_file in sorted(init_d_path.iterdir())
                    if script_file.is_file()
                ]

            # rc.local runs at the end of the boot sequence — worth checking
            rc_local_path = self.target_root / "etc" / "rc.local"
            if rc_local_path.exists():
                startup_data["rc_local"] = _read_file(str(rc_local_path))

        elif IS_WINDOWS:
            # These registry keys are the classic Windows autorun locations
            autorun_registry_keys = [
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ]
            for registry_key in autorun_registry_keys:
                registry_output, _, _ = _run(["reg", "query", registry_key])
                startup_data[registry_key] = registry_output

            # Also check the startup folder
            startup_folder_output, _, _ = _run(
                ["cmd", "/c", "dir",
                 r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"]
            )
            startup_data["startup_folder"] = startup_folder_output

        self._add_evidence(make_evidence(
            category="Persistence",
            title="Startup / Autorun Items",
            data=startup_data,
            source="systemd / registry / rc.local",
        ))

    # ------------------------------------------------------------------
    # 8. Recently modified files
    # ------------------------------------------------------------------

    def collect_recent_files(self) -> None:
        """
        Walk the target root and find files modified within the last
        recent_hours hours.

        This is one of the most useful collectors for incident response —
        if something was dropped on the system recently, it will show up here.
        The 1000-file limit is to prevent runaway collection on busy filesystems;
        increase it in the source if you need more coverage.
        """
        self._log(
            f"Collecting files modified in last {self.recent_hours}h "
            f"under {self.target_root} ..."
        )
        # Calculate the cutoff timestamp — anything modified after this counts
        modification_cutoff_timestamp = time.time() - self.recent_hours * 3600
        recently_modified_files: List[Dict] = []
        max_file_count = 1000

        # Skip virtual/pseudo filesystems — they're not real files and will
        # slow the walk to a crawl or return garbage results
        paths_to_skip = {"/proc", "/sys", "/dev", "/run"}

        try:
            for directory_path, subdirectory_names, file_names in os.walk(
                str(self.target_root), followlinks=False
            ):
                # Prune virtual filesystems from the walk in-place
                absolute_directory = os.path.abspath(directory_path)
                if any(absolute_directory.startswith(skip_path) for skip_path in paths_to_skip):
                    subdirectory_names.clear()
                    continue

                for file_name in file_names:
                    full_file_path = os.path.join(directory_path, file_name)
                    try:
                        file_stat = os.lstat(full_file_path)
                        if file_stat.st_mtime >= modification_cutoff_timestamp:
                            recently_modified_files.append({
                                "path":  full_file_path,
                                "size":  file_stat.st_size,
                                "mtime": datetime.datetime.fromtimestamp(
                                    file_stat.st_mtime).isoformat(),
                                "mode":  oct(file_stat.st_mode),
                                "uid":   file_stat.st_uid,
                                "gid":   file_stat.st_gid,
                            })
                            if len(recently_modified_files) >= max_file_count:
                                break
                    except (PermissionError, OSError):
                        continue
                if len(recently_modified_files) >= max_file_count:
                    break
        except (PermissionError, OSError):
            pass

        self._add_evidence(make_evidence(
            category="Filesystem",
            title=f"Recently Modified Files (last {self.recent_hours}h)",
            data={
                "count":  len(recently_modified_files),
                "limit":  max_file_count,
                "cutoff": datetime.datetime.fromtimestamp(modification_cutoff_timestamp).isoformat(),
                "files":  recently_modified_files,
            },
            source=str(self.target_root),
        ))

    # ------------------------------------------------------------------
    # 9. Log excerpts
    # ------------------------------------------------------------------

    def collect_logs(self) -> None:
        """
        Collect recent entries from key system logs.

        We read the tail of each log file (last 200 lines) to keep the
        output manageable. On live Linux systems we also query journalctl
        for warning-level and above entries, which is often the most useful
        filter for spotting anomalies.
        """
        self._log("Collecting log excerpts ...")
        log_data: Dict[str, Any] = {}

        if IS_LINUX:
            # Standard log file locations — not all will exist depending on distro
            linux_log_files = [
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/kern.log",
                "/var/log/dpkg.log",
            ]
            for log_file_path in linux_log_files:
                full_log_path = self.target_root / log_file_path.lstrip("/")
                if full_log_path.exists():
                    log_data[log_file_path] = _read_file(str(full_log_path), max_lines=200)

            # journalctl only works on a live system
            if str(self.target_root) in ("/", ""):
                journalctl_output, _, _ = _run(
                    ["journalctl", "-n", "200", "--no-pager", "-p", "warning"]
                )
                log_data["journalctl_warnings"] = journalctl_output

        elif IS_WINDOWS:
            # Pull the last 50 events from the three main Windows event logs
            for event_log_name in ("System", "Application", "Security"):
                event_log_output, _, _ = _run(
                    ["wevtutil", "qe", event_log_name,
                     "/c:50", "/rd:true", "/f:text"],
                    timeout=45,
                )
                log_data[f"EventLog_{event_log_name}"] = event_log_output[:5000]

        elif IS_MAC:
            unified_log_output, _, _ = _run(["log", "show", "--last", "1h", "--style", "compact"])
            log_data["unified_log"] = unified_log_output[:8000]

        self._add_evidence(make_evidence(
            category="Logs",
            title="System Log Excerpts",
            data=log_data,
            source="/var/log / journalctl / wevtutil",
        ))

    # ------------------------------------------------------------------
    # 10. Open file handles (Linux lsof)
    # ------------------------------------------------------------------

    def collect_open_handles(self) -> None:
        """
        Collect open file handles via lsof (Linux/macOS) or handle.exe (Windows).

        This shows what files processes currently have open, which can reveal
        things like malware writing to unusual locations or processes holding
        locks on files they shouldn't be touching. handle.exe is a Sysinternals
        tool and may not be installed — we degrade gracefully if it isn't.
        """
        self._log("Collecting open file handles ...")

        if IS_WINDOWS:
            # handle.exe is optional — not present on all Windows systems
            handles_output, handles_error, handles_return_code = _run(
                ["handle.exe", "-accepteula", "-a"], timeout=30
            )
            raw_handles_text = handles_output if handles_return_code == 0 else \
                f"handle.exe not available: {handles_error}"
        else:
            lsof_output, lsof_error, lsof_return_code = _run(
                ["lsof", "-n", "-P", "+c", "15"], timeout=30
            )
            raw_handles_text = lsof_output if lsof_return_code == 0 else \
                f"lsof error: {lsof_error}"

        self._add_evidence(make_evidence(
            category="Filesystem",
            title="Open File Handles",
            data={"raw_output": raw_handles_text[:10000]},
            source="lsof / handle.exe",
        ))

    # ------------------------------------------------------------------
    # Master runner
    # ------------------------------------------------------------------

    def run_all(self) -> List[Dict]:
        """
        Run every collector in volatility order and return the evidence list.

        Volatility order means most ephemeral data first (processes, network)
        and most stable data last (filesystem, logs). This follows the RFC 3227
        order-of-volatility guidance for digital forensics.

        Each collector is wrapped in a try/except so a failure in one (e.g.
        a permission error on a log file) doesn't abort the entire collection.
        """
        all_collectors = [
            self.collect_system_info,
            self.collect_processes,
            self.collect_network,
            self.collect_dns,
            self.collect_users,
            self.collect_scheduled_tasks,
            self.collect_startup_items,
            self.collect_recent_files,
            self.collect_logs,
            self.collect_open_handles,
        ]
        for collector_method in all_collectors:
            try:
                collector_method()
            except Exception as exc:  # noqa: BLE001
                collector_name = getattr(collector_method, "__name__", repr(collector_method))
                self._log(f"[WARN] {collector_name} failed: {exc}")
        return self.evidence


# ============================================================================
# Report generators
# ============================================================================

class ReportGenerator:
    """
    Takes the collected evidence list and writes it out in three formats:
    a JSON evidence file, an interactive HTML report, and a SHA-256 manifest.

    I split this into its own class so it's independently testable — you can
    pass in any evidence list and verify the output without running a real
    collection.
    """

    def __init__(self, evidence: List[Dict], output_dir: Path,
                 case_id: str = ""):
        self.evidence   = evidence
        self.output_dir = output_dir
        # Auto-generate a case ID if none was provided
        self.case_id    = case_id or datetime.datetime.now(datetime.timezone.utc).strftime(
            "CASE-%Y%m%d-%H%M%S"
        )
        output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # JSON output
    # ------------------------------------------------------------------

    def write_json(self) -> Path:
        """
        Write the evidence to a structured JSON file.

        The JSON is the canonical machine-readable output — other tools can
        parse it, and it's what you'd use if you wanted to analyze the data
        programmatically rather than reading the HTML report.
        """
        evidence_payload = {
            "case_id":    self.case_id,
            "generated":  datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "collector":  "ForensicKit 1.0.0",
            "host":       socket.gethostname(),
            "evidence":   self.evidence,
        }
        json_output_path = self.output_dir / f"{self.case_id}_evidence.json"
        with open(json_output_path, "w", encoding="utf-8") as file_handle:
            json.dump(evidence_payload, file_handle, indent=2, default=str)
        return json_output_path

    # ------------------------------------------------------------------
    # HTML output
    # ------------------------------------------------------------------

    def write_html(self) -> Path:
        """
        Write an interactive HTML report.

        The report is fully self-contained — no external dependencies, no
        internet required. I used a dark theme because it's easier to read
        on a monitor for long analysis sessions. Evidence is grouped by
        category with a sticky sidebar for navigation.
        """
        html_output_path = self.output_dir / f"{self.case_id}_report.html"

        # Group evidence items by category for the sidebar and sections
        evidence_by_category: Dict[str, List[Dict]] = {}
        for evidence_item in self.evidence:
            evidence_by_category.setdefault(evidence_item["category"], []).append(evidence_item)

        # Build sidebar navigation links
        nav_items = "".join(
            f'<li><a href="#{category_name.lower()}">{category_name}</a></li>'
            for category_name in evidence_by_category
        )

        # Build the main content sections
        sections_html = ""
        for category_name, category_items in evidence_by_category.items():
            category_cards_html = ""
            for evidence_item in category_items:
                rendered_data_html = self._render_data(evidence_item["data"])
                category_cards_html += f"""
<div class="card">
  <div class="card-header">
    <h3>{evidence_item['title']}</h3>
    <span class="meta">Source: {evidence_item['source']} &nbsp;|&nbsp; {evidence_item['timestamp']}</span>
  </div>
  <div class="card-body">{rendered_data_html}</div>
</div>
"""
            sections_html += f"""
<section id="{category_name.lower()}">
  <h2 class="section-title">{category_name}</h2>
  {category_cards_html}
</section>
"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ForensicKit Report — {self.case_id}</title>
<style>
  :root {{
    --bg:        #0d1117;
    --surface:   #161b22;
    --surface2:  #21262d;
    --border:    #30363d;
    --accent:    #58a6ff;
    --accent2:   #f78166;
    --text:      #c9d1d9;
    --text-dim:  #8b949e;
    --green:     #3fb950;
    --yellow:    #e3b341;
    --red:       #f85149;
    --mono:      'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
    --sans:      'Inter', 'Segoe UI', system-ui, sans-serif;
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text);
    display: grid;
    grid-template-columns: 220px 1fr;
    min-height: 100vh;
  }}
  /* Sidebar */
  aside {{
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
    background: var(--surface);
    border-right: 1px solid var(--border);
    padding: 1.5rem 0;
  }}
  .logo {{
    padding: 0 1.25rem 1.5rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1rem;
  }}
  .logo h1 {{
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: .04em;
  }}
  .logo p {{ font-size: .7rem; color: var(--text-dim); margin-top: .2rem; }}
  aside ul {{ list-style: none; }}
  aside li a {{
    display: block;
    padding: .45rem 1.25rem;
    color: var(--text-dim);
    text-decoration: none;
    font-size: .82rem;
    border-left: 3px solid transparent;
    transition: .15s;
    text-transform: uppercase;
    letter-spacing: .06em;
  }}
  aside li a:hover {{
    color: var(--accent);
    border-color: var(--accent);
    background: rgba(88,166,255,.07);
  }}
  /* Main */
  main {{
    padding: 2rem 2.5rem;
    overflow: auto;
  }}
  .report-header {{
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
  }}
  .report-header h1 {{
    font-size: 1.5rem;
    color: var(--accent);
    font-weight: 700;
  }}
  .report-header .meta {{ color: var(--text-dim); font-size: .8rem; margin-top: .4rem; }}
  .badge {{
    display: inline-block;
    padding: .2rem .6rem;
    border-radius: 2rem;
    font-size: .7rem;
    font-weight: 700;
    background: rgba(88,166,255,.15);
    color: var(--accent);
    letter-spacing: .04em;
    margin-right: .5rem;
  }}
  section {{ margin-bottom: 3rem; }}
  .section-title {{
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--accent2);
    text-transform: uppercase;
    letter-spacing: .1em;
    margin-bottom: 1rem;
    padding-bottom: .5rem;
    border-bottom: 1px solid var(--border);
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 1.2rem;
    overflow: hidden;
  }}
  .card-header {{
    padding: .75rem 1.25rem;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    flex-wrap: wrap;
    gap: .5rem;
  }}
  .card-header h3 {{ font-size: .9rem; font-weight: 600; color: var(--text); }}
  .card-header .meta {{ font-size: .7rem; color: var(--text-dim); }}
  .card-body {{ padding: 1rem 1.25rem; }}
  /* Tables */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: .78rem;
    margin-top: .5rem;
  }}
  th {{
    text-align: left;
    padding: .4rem .6rem;
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--text-dim);
    font-weight: 600;
    text-transform: uppercase;
    font-size: .68rem;
    letter-spacing: .05em;
  }}
  td {{
    padding: .35rem .6rem;
    border: 1px solid var(--border);
    color: var(--text);
    word-break: break-all;
    max-width: 40ch;
  }}
  tr:nth-child(even) td {{ background: rgba(255,255,255,.02); }}
  /* Pre */
  pre {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: .75rem 1rem;
    font-family: var(--mono);
    font-size: .75rem;
    line-height: 1.5;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--green);
    max-height: 400px;
  }}
  .kv-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px,1fr));
    gap: .5rem;
  }}
  .kv-item {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: .5rem .75rem;
  }}
  .kv-item .key {{
    font-size: .65rem;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: .06em;
  }}
  .kv-item .val {{
    font-size: .82rem;
    color: var(--accent);
    font-family: var(--mono);
    margin-top: .15rem;
    word-break: break-all;
  }}
  /* Scrollbar */
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
</style>
</head>
<body>
<aside>
  <div class="logo">
    <h1>ForensicKit</h1>
    <p>Digital Forensic Report</p>
  </div>
  <ul>{nav_items}</ul>
</aside>
<main>
  <div class="report-header">
    <h1>Forensic Evidence Report</h1>
    <div class="meta">
      <span class="badge">Case ID</span>{self.case_id} &nbsp;|&nbsp;
      <span class="badge">Host</span>{socket.gethostname()} &nbsp;|&nbsp;
      <span class="badge">Generated</span>{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
      &nbsp;|&nbsp;
      <span class="badge">Artifacts</span>{len(self.evidence)}
    </div>
  </div>
  {sections_html}
</main>
</body>
</html>"""

        with open(html_output_path, "w", encoding="utf-8") as file_handle:
            file_handle.write(html)
        return html_output_path

    # ------------------------------------------------------------------
    # HTML rendering helpers
    # ------------------------------------------------------------------

    def _render_data(self, data: Any, recursion_depth: int = 0) -> str:
        """
        Recursively render any Python data structure as HTML.

        The logic picks the most readable representation for each type:
        - strings get <code> or <pre> depending on length
        - lists of dicts become sortable tables
        - flat dicts become key-value grids
        - nested dicts become collapsible <details> trees
        The depth limit stops runaway recursion on deeply nested structures.
        """
        if recursion_depth > 4:
            return f"<pre>{str(data)[:2000]}</pre>"

        if isinstance(data, str):
            if "\n" in data or len(data) > 120:
                return f"<pre>{self._escape(data[:8000])}</pre>"
            return f"<code>{self._escape(data)}</code>"

        if isinstance(data, (int, float, bool)):
            return f"<code>{data}</code>"

        if isinstance(data, list):
            if not data:
                return "<em style='color:var(--text-dim)'>empty</em>"
            # A list of dicts renders best as a table
            if all(isinstance(item, dict) for item in data):
                return self._render_table(data)
            return "<pre>" + self._escape(
                "\n".join(str(item) for item in data[:200])
            ) + "</pre>"

        if isinstance(data, dict):
            # Flat key/value pairs with simple values get the grid layout
            if all(isinstance(value, (str, int, float, bool, type(None)))
                   for value in data.values()) and len(data) <= 20:
                grid_items_html = "".join(
                    f'<div class="kv-item"><div class="key">{self._escape(str(key))}'
                    f'</div><div class="val">{self._escape(str(value))}</div></div>'
                    for key, value in data.items()
                )
                return f'<div class="kv-grid">{grid_items_html}</div>'
            # Nested structures get collapsible details elements
            nested_parts = []
            for key, value in data.items():
                nested_parts.append(
                    f"<details open><summary style='cursor:pointer;"
                    f"color:var(--text-dim);font-size:.78rem;padding:.3rem 0'>"
                    f"<strong>{self._escape(str(key))}</strong></summary>"
                    f"<div style='margin:.5rem 0 .5rem 1rem'>"
                    f"{self._render_data(value, recursion_depth + 1)}</div></details>"
                )
            return "".join(nested_parts)

        return f"<pre>{self._escape(str(data)[:4000])}</pre>"

    def _render_table(self, table_rows: List[Dict]) -> str:
        """
        Render a list of dicts as an HTML table.

        Capped at 500 rows and 15 columns to keep the report from getting
        unmanageably large for things like a full process list.
        """
        if not table_rows:
            return ""
        # Use the first row's keys as column headers, up to 15 columns
        column_keys = list(table_rows[0].keys())[:15]
        table_header_html = "".join(
            f"<th>{self._escape(str(key))}</th>" for key in column_keys
        )
        table_body_html = ""
        for row in table_rows[:500]:
            row_cells_html = "".join(
                f"<td>{self._escape(str(row.get(key, '')))[:120]}</td>"
                for key in column_keys
            )
            table_body_html += f"<tr>{row_cells_html}</tr>"
        return f"<table><thead><tr>{table_header_html}</tr></thead><tbody>{table_body_html}</tbody></table>"

    @staticmethod
    def _escape(raw_string: str) -> str:
        """
        Escape HTML special characters to prevent XSS in the report.

        This is applied to all user-controlled data before it goes into the HTML.
        """
        return (raw_string.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
                 .replace('"', "&quot;"))

    # ------------------------------------------------------------------
    # SHA-256 manifest
    # ------------------------------------------------------------------

    def write_manifest(self, extra_files: Optional[List[Path]] = None) -> Path:
        """
        Write a SHA-256 manifest of all output files.

        The manifest records a hash for each output file so you can verify
        nothing was changed after collection. The manifest itself is excluded
        from its own hash list (you can't hash a file you're still writing).
        """
        manifest_output_path = self.output_dir / f"{self.case_id}_manifest.txt"
        files_to_hash = list(self.output_dir.glob("*"))
        if extra_files:
            files_to_hash.extend(extra_files)

        manifest_lines = [
            f"# ForensicKit SHA-256 Manifest",
            f"# Case: {self.case_id}",
            f"# Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
            "",
        ]
        for file_path in sorted(set(files_to_hash)):
            # Skip the manifest itself — we can't hash a file we're currently writing
            if file_path == manifest_output_path:
                continue
            file_digest = _sha256_file(str(file_path)) or "ERROR"
            manifest_lines.append(f"{file_digest}  {file_path.name}")

        with open(manifest_output_path, "w", encoding="utf-8") as file_handle:
            file_handle.write("\n".join(manifest_lines) + "\n")
        return manifest_output_path


# ============================================================================
# CLI entry-point
# ============================================================================

def build_argument_parser() -> argparse.ArgumentParser:
    """Build and return the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="forensic_collector.py",
        description=textwrap.dedent("""\
            ForensicKit - Forensic Artifact Collector
            Gathers evidence from a live system or mounted disk image.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python forensic_collector.py -v
              python forensic_collector.py -t /mnt/evidence -o /tmp/case001
              python forensic_collector.py -r 48 -v --no-html
        """),
    )
    parser.add_argument("-o", "--output",  default="reports",
                   help="Output directory for the report (default: ./reports)")
    parser.add_argument("-t", "--target",  default="/",
                   help="Root of mounted image or live system (default: /)")
    parser.add_argument("-r", "--recent",  type=int, default=24,
                   help="Hours back for recent-files search (default: 24)")
    parser.add_argument("-v", "--verbose", action="store_true",
                   help="Print progress messages")
    parser.add_argument("--case-id",       default="",
                   help="Custom case identifier (auto-generated if omitted)")
    parser.add_argument("--no-html",       action="store_true",
                   help="Skip HTML report")
    parser.add_argument("--no-hash",       action="store_true",
                   help="Skip SHA-256 manifest")
    return parser


# Keep the old name as an alias so existing tests that call build_parser() still work
build_parser = build_argument_parser


def main(argv: Optional[List[str]] = None) -> int:
    parsed_args = build_argument_parser().parse_args(argv)

    print("=" * 60)
    print("  ForensicKit v1.0.0 - Digital Artifact Collector")
    print("=" * 60)
    if not HAS_PSUTIL:
        print("[WARN] psutil not installed. Install it for richer data:")
        print("       pip install psutil")

    collector = ForensicCollector(
        target_root  = parsed_args.target,
        recent_hours = parsed_args.recent,
        verbose      = parsed_args.verbose,
    )

    print(f"[*] Target root  : {parsed_args.target}")
    print(f"[*] Output dir   : {parsed_args.output}")
    print(f"[*] Recent files : last {parsed_args.recent}h")
    print("[*] Collecting artifacts ...")

    collected_evidence = collector.run_all()
    print(f"[+] Collected {len(collected_evidence)} artifact sets.")

    output_directory = Path(parsed_args.output)
    report_generator = ReportGenerator(collected_evidence, output_directory,
                                       case_id=parsed_args.case_id)

    print("[*] Writing JSON evidence file ...")
    json_output_path = report_generator.write_json()
    print(f"    -> {json_output_path}")

    if not parsed_args.no_html:
        print("[*] Writing HTML report ...")
        html_output_path = report_generator.write_html()
        print(f"    -> {html_output_path}")

    if not parsed_args.no_hash:
        print("[*] Writing SHA-256 manifest ...")
        manifest_output_path = report_generator.write_manifest()
        print(f"    -> {manifest_output_path}")

    print("[+] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
