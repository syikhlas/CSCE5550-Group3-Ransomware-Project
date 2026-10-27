#!/usr/bin/env python3
"""CSCE 5550 defensive mitigation demo: backup, alert, dry-run, recovery."""
import argparse
import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE = Path.home() / 'CSCE5550-Group3'
SOURCE = BASE / 'test_data'
BACKUP = BASE / 'protected_backup'
MANIFEST = BASE / 'backup_hashes.json'
DB = BASE / 'incidents.sqlite3'

def hashes(folder):
    return {str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob('*')) if p.is_file() and not p.is_symlink()}

def backup():
    if not SOURCE.is_dir():
        raise RuntimeError('Test data missing; create test_data first')
    if BACKUP.exists() or MANIFEST.exists():
        raise RuntimeError('Backup already exists; refusing to overwrite it')
    shutil.copytree(SOURCE, BACKUP, symlinks=False)
    expected = hashes(SOURCE)
    if hashes(BACKUP) != expected:
        raise RuntimeError('Backup verification failed')
    MANIFEST.write_text(json.dumps(expected, indent=2))
    print(f'BACKUP PASS: {len(expected)} files verified in {BACKUP}')

def alert(reason):
    BASE.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, timestamp TEXT, severity TEXT, reason TEXT, action TEXT)')
        conn.execute('INSERT INTO incidents(timestamp,severity,reason,action) VALUES (?,?,?,?)',
                     (datetime.now(timezone.utc).isoformat(), 'HIGH', reason, 'DRY RUN: investigate and isolate suspected process'))
    print(f'ALERT: {reason}\nCONTAINMENT DRY RUN: investigate PID and isolate VM after confirmation; no processes terminated.')

def restore():
    if not BACKUP.is_dir() or not MANIFEST.is_file():
        raise RuntimeError('Verified backup and manifest required')
    expected = json.loads(MANIFEST.read_text())
    if hashes(BACKUP) != expected:
        raise RuntimeError('Backup integrity mismatch; refusing recovery')
    SOURCE.mkdir(parents=True, exist_ok=True)
    for rel in expected:
        origin = BACKUP / rel
        target = SOURCE / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, target)
    actual = hashes(SOURCE)
    if actual != expected:
        raise RuntimeError('Restoration verification failed (unexpected or changed files)')
    print(f'RESTORE PASS: all {len(expected)} test files match original SHA-256 hashes')

def show():
    if not DB.exists():
        print('No incidents recorded yet')
        return
    with sqlite3.connect(DB) as conn:
        for record in conn.execute('SELECT id,timestamp,severity,reason,action FROM incidents ORDER BY id DESC'):
            print(record)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['backup', 'alert', 'restore', 'incidents'])
    parser.add_argument('--reason', default='Simulated suspicious file modifications')
    args = parser.parse_args()
    try:
        {'backup': backup, 'alert': lambda: alert(args.reason), 'restore': restore, 'incidents': show}[args.command]()
    except (OSError, RuntimeError, ValueError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
