#!/usr/bin/env python3
# =============================================================================
# CSCE 5550 - Ransomware Project
# monitor.py -- MONITORING + DETECTION component (runs on the VICTIM VM)
#
# What this file does and why:
#
#   1. MONITORING: the kernel (auditd) generates an event every time a process
#      writes/creates/renames/deletes a file inside the watched directory
#      (rule: auditctl -w /home/osboxes/Desktop/critical_abcde -p wa
#       -k ransomwatch). This script tails /var/log/audit/audit.log, parses
#      those events and stores each one as a structured row in SQLite
#      (course requirement: monitored data must be logged in a database or
#      other structured file).
#
#   2. DETECTION: for every event the executable of the offending process is
#      checked against an ALLOWLIST of legitimate tools. Any process NOT on
#      the list that successfully modifies a file in the protected directory
#      is flagged immediately. This catches unknown malware without
#      signatures and produces zero false positives for known-good tools.
#
#   3. ALERT: on the first violation per process, auditd_bridge.py is called
#      with the PID and the executable path; the bridge forwards the alert to
#      mitigate.py (incident logging + process containment + recovery).
#
# Why auditd and not watchdog/inotify: inotify only says WHAT changed, not
# WHO did it. auditd events carry the PID and the exe path -- without them
# the mitigation would not know which process to terminate.
#
# RUN WITH:  sudo python3 monitor.py     (/var/log/audit/audit.log is root-only)
# Stop with Ctrl+C. Note: auditctl rules do NOT survive a reboot.
# =============================================================================

import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

# ----------------------------- configuration ---------------------------------
AUDIT_LOG = "/var/log/audit/audit.log"
WATCH_KEY = "ransomwatch"          # must match the auditctl rule's -k
DB_FILE = Path(__file__).resolve().parent / "monitor_events.sqlite3"
BRIDGE = Path(__file__).resolve().parent / "auditd_bridge.py"
MITIGATE_SCRIPT = os.path.realpath(Path(__file__).resolve().parent / "mitigate.py")

# Processes allowed to modify files in the protected directory (full exe
# paths, because a malicious process can masquerade under a known NAME).
# NOTE: /usr/bin/python3 is intentionally NOT listed: the lab ransomware can
# be executed as "python3 encryption.py ...", so python3 must stay flagged.
ALLOWED_EXECUTABLES = {
    "/usr/bin/gedit", "/usr/bin/vim", "/usr/bin/vi", "/usr/bin/nano",
    "/usr/bin/cp", "/usr/bin/mv", "/usr/bin/rsync", "/usr/bin/tar",
    "/usr/bin/unzip", "/usr/bin/mkdir", "/usr/bin/gnome-text-editor",
}

ALERT_COOLDOWN_SECONDS = 10        # don't re-alert for the same PID

# ------------------------------ sqlite setup ---------------------------------

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""CREATE TABLE IF NOT EXISTS file_events(
        id INTEGER PRIMARY KEY, ts TEXT, serial TEXT, pid INTEGER, exe TEXT,
        comm TEXT, syscall TEXT, success TEXT, path TEXT, verdict TEXT)""")
    conn.commit()
    return conn

# ------------------------------ preflight checks -----------------------------

def preflight():
    """Fail fast with a clear message instead of silently showing nothing."""
    problems = []
    am_root = os.geteuid() == 0

    # The auditctl checks below only work as root: without sudo, auditctl
    # cannot talk to the kernel and would produce FALSE "rule missing" alarms.
    if am_root:
        # 1. Is the audit daemon actually running? If auditd is down, kernel
        #    events go to dmesg/journal, NOT to /var/log/audit/audit.log.
        try:
            out = subprocess.run(["auditctl", "-s"], capture_output=True, text=True)
            status = out.stdout
            if "pid" in status:
                pid_line = [l for l in status.splitlines() if l.strip().startswith("pid")]
                if pid_line and pid_line[0].split()[-1] == "0":
                    problems.append(
                        "auditd is NOT running (kernel pid = 0): events never reach "
                        "/var/log/audit/audit.log. Fix:\n"
                        "  sudo systemctl enable --now auditd")
            if "enabled" in status:
                en_line = [l for l in status.splitlines() if l.strip().startswith("enabled")]
                if en_line and en_line[0].split()[-1] not in ("1", "2"):
                    problems.append(
                        "kernel auditing is disabled (auditctl -s: enabled != 1). Fix:\n"
                        "  sudo systemctl enable --now auditd")
        except FileNotFoundError:
            problems.append("auditctl not found: sudo apt install auditd")

        # 2. Is our watch rule loaded? (Rules do NOT survive a reboot!)
        try:
            out = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
            if WATCH_KEY not in out.stdout:
                problems.append(
                    f"no audit rule with key '{WATCH_KEY}' is loaded. Fix:\n"
                    f"  sudo auditctl -w /home/osboxes/Desktop/critical_abcde -p wa -k {WATCH_KEY}")
        except FileNotFoundError:
            pass  # already reported above
    else:
        print("[monitor] NOTE: not running as root — audit rule and daemon checks")
        print("[monitor] NOTE: are skipped (auditctl needs root). If no events appear,")
        print("[monitor] NOTE: verify with:  sudo auditctl -l   (and run with sudo).")

    # 3. Can we read the log file?
    if not os.path.isfile(AUDIT_LOG):
        problems.append(
            f"audit log not found: {AUDIT_LOG}\n"
            "  -> auditd installed and started? (sudo apt install auditd && "
            "sudo systemctl enable --now auditd)")
    else:
        try:
            with open(AUDIT_LOG):
                pass
        except PermissionError:
            problems.append(
                "audit log is not readable by this user. Run with sudo:\n"
                "  sudo python3 monitor.py")

    # 4. Are the other pipeline files present next to this script?
    here = Path(__file__).resolve().parent
    for name in ("auditd_bridge.py", "mitigate.py"):
        if not (here / name).is_file():
            problems.append(
                f"{name} not found next to monitor.py ({here}) — copy it there, "
                "otherwise alerts can never reach the mitigation system.")

    for p in problems:
        print(f"[monitor] PROBLEM: {p}")
    if problems:
        print("[monitor] fix the problems above, then restart this script.")
    return not problems


# ------------------------------ auditd parsing -------------------------------
# One audit event = several log records sharing the same serial number, e.g.
#   type=SYSCALL msg=audit(1731012345.123:456) ... pid=1234 ... exe="/tmp/encrypt" ... key="ransomwatch"
#   type=PATH    msg=audit(1731012345.123:456) ... name="/home/.../file.txt" ...
# SYSCALL always comes first and carries pid/exe/key; PATH carries the file.

SERIAL_RE = re.compile(r"msg=audit\((\d+\.\d+:\d+)\)")
FIELD_RE = re.compile(r'(\w+)="([^"]*)"|(\w+)=([^\s]+)')


def parse_fields(line):
    fields = {}
    for m in FIELD_RE.finditer(line):
        if m.group(1):
            fields[m.group(1)] = m.group(2)
        else:
            fields[m.group(3)] = m.group(4)
    return fields


def follow_log(path):
    """Yield new audit.log lines as they are written (like `tail -f`)."""
    with open(path, "r", errors="replace") as f:
        f.seek(0, os.SEEK_END)          # skip history: only NEW events matter
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.2)

# ------------------------------ detection logic ------------------------------

# PIDs already identified as our recovery tool. Once /proc/PID/cmdline has
# confirmed "mitigate.py", we trust that PID for the rest of its life: the
# monitor processes audit events with a small delay, and if it evaluates the
# LAST events of a restore after the process has already exited, /proc/PID
# no longer exists and the cmdline check would fail -- making the monitor
# flag its own completed recovery as suspicious (ALLOW->ALERT flip). Caching
# the classification removes that artifact. (PID reuse is not a concern on
# the lab timescale.)
MAINTENANCE_PIDS = set()


def is_maintenance_tool(pid, exe):
    """The team's own recovery tool is authorized to write to the protected
    directory during backup/restore. Without this exception the monitor would
    detect mitigate.py restore mid-recovery and kill it (the defender shooting
    its own recovery tool). We check /proc/PID/cmdline so that ONLY processes
    running mitigate.py are exempt -- "python3 encryption.py" is still flagged.
    """
    if not exe.startswith("/usr/bin/python3"):
        return False
    try:
        args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        if len(args) < 2 or not args[1]:
            return False
        script = args[1].decode("utf-8", "replace")
        # Resolve a relative script name against the process's own cwd.
        cwd = os.readlink(f"/proc/{pid}/cwd")
        resolved = os.path.realpath(os.path.join(cwd, script))
        return resolved == MITIGATE_SCRIPT
    except OSError:
        return False









def evaluate(conn, ev, last_alert):
    """Log one file event, then alert if the process is not allowlisted."""
    if ev["pid"] in MAINTENANCE_PIDS:
        allowed = True
    else:
        allowed = ev["exe"] in ALLOWED_EXECUTABLES
        if not allowed and is_maintenance_tool(ev["pid"], ev["exe"]):
            MAINTENANCE_PIDS.add(ev["pid"])
            allowed = True
    verdict = "ALLOW" if allowed else "ALERT"
    path_str = "; ".join(ev["paths"]) or "(no path)"

    conn.execute(
        "INSERT INTO file_events(ts,serial,pid,exe,comm,syscall,success,path,verdict)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (ev["ts"], ev["serial"], ev["pid"], ev["exe"], ev["comm"],
         ev["syscall"], ev["success"], path_str, verdict))
    conn.commit()
    print(f"[{verdict}] pid={ev['pid']} exe={ev['exe']} "
          f"syscall={ev['syscall']} path={path_str}")

    # Only alert on successful operations by non-allowlisted processes.
    if allowed or ev["success"] != "yes":
        return

    now = time.time()
    if ev["pid"] in last_alert and now - last_alert[ev["pid"]] < ALERT_COOLDOWN_SECONDS:
        return
    last_alert[ev["pid"]] = now
    send_alert(ev, path_str)


def send_alert(ev, path_str):
    reason = (f"Non-allowlisted process {ev['exe']} (pid {ev['pid']}) "
              f"modified protected file(s): {path_str}")
    print(f"[monitor] ALERT -> forwarding to mitigation: {reason}", flush=True)
    subprocess.run(
        [sys.executable, str(BRIDGE), "--reason", reason,
         "--source", "monitor.py", "--pid", str(ev["pid"]), "--exe", ev["exe"]],
        check=False)

# ---------------------------------- main -------------------------------------

def main():
    preflight()
    conn = init_db()
    pending = {}      # serial -> partially parsed event (SYSCALL seen, PATH not yet)
    last_alert = {}   # pid -> last alert timestamp

    print(f"[monitor] watching audit key '{WATCH_KEY}' on {AUDIT_LOG}")
    print(f"[monitor] allowlist: {sorted(ALLOWED_EXECUTABLES)}")
    print("[monitor] press Ctrl+C to stop", flush=True)

    for line in follow_log(AUDIT_LOG):
        m = SERIAL_RE.search(line)
        if not m:
            continue
        serial = m.group(1)
        fields = parse_fields(line)

        if "type=SYSCALL" in line:
            if fields.get("key") == WATCH_KEY:
                pending[serial] = {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "serial": serial,
                    "pid": int(fields.get("pid", 0) or 0),
                    "exe": fields.get("exe", "?"),
                    "comm": fields.get("comm", "?"),
                    "syscall": fields.get("syscall", "?"),
                    "success": fields.get("success", "?"),
                    "paths": [],
                }
            else:
                pending.pop(serial, None)      # different watch key: ignore
        elif serial in pending and "type=PATH" in line:
            name = fields.get("name")
            if name:
                pending[serial]["paths"].append(name)

        # Event complete (we have the file name) -> evaluate now.
        if serial in pending and pending[serial]["paths"]:
            ev = pending.pop(serial)
            evaluate(conn, ev, last_alert)

        # Safety valve: drop stale incomplete events.
        if len(pending) > 200:
            for k in list(pending)[:100]:
                pending.pop(k)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[monitor] stopped.")
