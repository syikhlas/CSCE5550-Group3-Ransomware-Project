#!/usr/bin/env python3
"""CSCE 5550 defensive mitigation: backup, alert + containment, recovery.

Corrected version of the original mitigation prototype, wired to the real
project directory and to the detection pipeline:

  1. backup  - verified backup of /home/osboxes/Desktop/critical_abcde
              (stored OUTSIDE the protected directory, so the ransomware
              cannot touch it). Refuses to overwrite an existing backup.
  2. alert   - records the incident in SQLite (now with PID and executable
              path) and CONTAINS the suspicious process: SIGSTOP (suspend,
              so it cannot encrypt anything more) followed by SIGKILL.
              Was a dry run before; the course requires "block it".
  3. restore - wipes the damaged directory (removes .locked_abcde files,
              key.bin.enc, ransom note and manifest) and rebuilds it from
              the verified backup, then checks every file against the
              SHA-256 manifest.
  4. incidents - shows the recorded incident log (evidence for the report).
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# --------------------------- configuration -----------------------------------
# The REAL ransomware target (was ~/CSCE5550-Group3/test_data in the prototype).
DEFAULT_SOURCE = Path('/home/osboxes/Desktop/critical_abcde')

# Backup lives OUTSIDE the protected directory ON PURPOSE: the ransomware only
# encrypts critical_abcde, so the backup survives even a completed attack.
# FIXED ABSOLUTE PATH: the alert chain (monitor.py -> bridge -> mitigate.py)
# runs as root because monitor.py needs sudo; under root, Path.home() would
# resolve to /root and the incident database would end up in a DIFFERENT file
# than the one read when running mitigate.py as the normal user.
BASE = Path('/home/osboxes/CSCE5550-Group3')
BACKUP = BASE / 'protected_backup'
MANIFEST = BASE / 'backup_hashes.json'
DB = BASE / 'incidents.sqlite3'

# Files the attack leaves behind; restore() removes them before verifying.
ATTACK_SUFFIXES = ('.locked_abcde',)
ATTACK_NAMES = ('key.bin.enc', 'README_RESTORE.txt', '.integrity_manifest.json')


def hashes(folder):
    return {str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob('*')) if p.is_file() and not p.is_symlink()}


def ensure_db():
    conn = sqlite3.connect(DB)
    conn.execute('CREATE TABLE IF NOT EXISTS incidents ('
                 'id INTEGER PRIMARY KEY, timestamp TEXT, severity TEXT, '
                 'reason TEXT, action TEXT, pid INTEGER, exe TEXT)')
    conn.commit()
    return conn


def backup(source):
    if not source.is_dir():
        raise RuntimeError(f'Protected directory missing: {source}')
    if BACKUP.exists() or MANIFEST.exists():
        raise RuntimeError('Backup already exists; refusing to overwrite it '
                           '(delete protected_backup/ and backup_hashes.json '
                           'to force a new one)')
    shutil.copytree(source, BACKUP, symlinks=False)
    expected = hashes(source)
    if hashes(BACKUP) != expected:
        raise RuntimeError('Backup verification failed')
    MANIFEST.write_text(json.dumps(expected, indent=2))
    print(f'BACKUP PASS: {len(expected)} files verified in {BACKUP}')


def alert(reason, pid=None, exe=None):
    BASE.mkdir(parents=True, exist_ok=True)
    conn = ensure_db()

    # ---- containment: suspend + kill the confirmed suspicious process ------
    action = 'No valid PID provided: logged only'
    # pid must be > 1: pid 0 would signal our own process group and
    # negative pids signal whole groups.
    if pid is not None and pid > 1:
        try:
            # Guard against PID reuse: the audit event is a little old, so
            # make sure this PID still runs the reported executable.
            current = None
            if exe:
                current = os.readlink(f'/proc/{pid}/exe').removesuffix(' (deleted)')
            if exe and current != exe:
                action = (f'SKIPPED: PID {pid} now runs {current}, not {exe} '
                          f'(process exited and PID was reused)')
            else:
                os.kill(pid, signal.SIGSTOP)   # suspend: no more file writes
                os.kill(pid, signal.SIGKILL)   # then terminate for good
                action = f'CONTAINED: SIGSTOP+SIGKILL sent to PID {pid}'
        except (ProcessLookupError, FileNotFoundError):
            action = f'PID {pid} already exited before containment'
        except PermissionError:
            action = f'Containment FAILED for PID {pid}: permission denied (run with sudo)'

    conn.execute('INSERT INTO incidents(timestamp,severity,reason,action,pid,exe)'
                 ' VALUES (?,?,?,?,?,?)',
                 (datetime.now(timezone.utc).isoformat(), 'HIGH',
                  reason, action, pid, exe))
    conn.commit()
    conn.close()
    print(f'ALERT: {reason}')
    print(f'ACTION: {action}')
    if exe:
        print(f'EXECUTABLE: {exe}')


def restore(source):
    if not BACKUP.is_dir() or not MANIFEST.is_file():
        raise RuntimeError('Verified backup and manifest required (run backup first)')
    expected = json.loads(MANIFEST.read_text())
    if hashes(BACKUP) != expected:
        raise RuntimeError('Backup integrity mismatch; refusing recovery')

    # ---- clean the damaged tree: attack artifacts + encrypted leftovers ----
    if source.exists():
        for p in sorted(source.rglob('*'), reverse=True):
            if p.is_file() and (p.name in ATTACK_NAMES
                                or any(p.name.endswith(s) for s in ATTACK_SUFFIXES)):
                p.unlink()
                print(f'  [clean] removed attack artifact: {p.name}')

    # ---- rebuild every expected file from the verified backup ---------------
    source.mkdir(parents=True, exist_ok=True)
    for rel in expected:
        origin = BACKUP / rel
        target = source / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, target)

    actual = hashes(source)
    if actual != expected:
        unexpected = sorted(set(actual) - set(expected))
        raise RuntimeError(f'Restoration verification failed. Unexpected files '
                           f'remain: {unexpected}')
    print(f'RESTORE PASS: all {len(expected)} files match original SHA-256 hashes')


def show():
    conn = ensure_db()
    rows = list(conn.execute(
        'SELECT id,timestamp,severity,reason,action,pid,exe '
        'FROM incidents ORDER BY id DESC'))
    conn.close()
    if not rows:
        print('No incidents recorded yet')
        return
    for r in rows:
        print(r)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['backup', 'alert', 'restore', 'incidents'])
    parser.add_argument('--reason', default='Suspicious file modifications')
    parser.add_argument('--pid', type=int)
    parser.add_argument('--exe')
    parser.add_argument('--source', default=str(DEFAULT_SOURCE),
                        help='protected directory (default: critical_abcde)')
    args = parser.parse_args()

    source = Path(args.source).expanduser()
    try:
        if args.command == 'backup':
            backup(source)
        elif args.command == 'alert':
            alert(args.reason, args.pid, args.exe)
        elif args.command == 'restore':
            restore(source)
        else:
            show()
    except (OSError, RuntimeError, ValueError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
