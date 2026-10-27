# Mitigation and Recovery — CSCE 5550 Group 3

## Overview

This component demonstrates a defensive response workflow for the Group 3 ransomware project using Python on Ubuntu 24.04.

## Implemented Features

- Backup creation for a directory containing test files
- Protection against accidental backup overwriting
- Simulated suspicious-activity alerts
- SQLite incident logging
- Dry-run containment recommendations
- File restoration from a known backup
- SHA-256 integrity verification

## Requirements

- Ubuntu 24.04
- Python 3

No third-party Python packages are required.

## Usage

Run these commands from the `mitigation` directory:

```bash
python3 mitigate.py backup
python3 mitigate.py alert --reason "Suspicious bulk file modifications"
python3 mitigate.py incidents
python3 mitigate.py restore
```

The program expects the test directory and backup paths configured in `mitigate.py`.

## Testing Results

The following tests were performed on an Ubuntu virtual machine:

| Test | Result |
|---|---|
| Backup of four sample files | PASS |
| Refusal to overwrite an existing backup | PASS |
| Simulated alert generation | PASS |
| Incident record retrieval | PASS |
| Restoration of modified file | PASS |
| SHA-256 verification | PASS |

## Current Limitations

The prototype uses simulated detection alerts. Automatic ransomware detection, live process containment, and integration with the team's `auditd` monitoring system are not yet implemented.

## Safety

All tests were performed using harmless sample files in an Ubuntu virtual machine. No ransomware execution was required to validate the recovery component.
