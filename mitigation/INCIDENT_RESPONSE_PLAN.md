# Incident Response Plan
## CSCE 5550 — Group 3 Ransomware Project

### 1. Purpose

This Incident Response Plan describes how our team intends to detect, contain, investigate, and recover from a simulated ransomware incident in an isolated Ubuntu virtual machine.

The objective is to minimize damage, preserve incident evidence, and restore important files.

### 2. Preparation

Before testing, the team will:

- Maintain an isolated Ubuntu virtual machine.
- Create backups of important test files.
- Record SHA-256 hashes to verify file integrity.
- Prepare incident logging and recovery procedures.
- Maintain a clean VirtualBox snapshot for emergency recovery.

### 3. Detection and Analysis

The planned detection system uses Linux `auditd` to monitor suspicious file activity.

Potential indicators include:

- Unusual numbers of file modifications.
- Rapid changes to files in the monitored directory.
- Suspicious processes accessing protected files.
- Unexpected file deletion or modification.

Detection alerts will eventually be passed to the mitigation component.

The current mitigation prototype accepts simulated alerts and records incidents using SQLite.

### 4. Containment

When suspicious activity is identified, the team will:

1. Record the incident timestamp and reason.
2. Review the suspicious process and relevant audit logs.
3. Confirm whether the activity is malicious.
4. Isolate the affected VM from the network if necessary.
5. Stop the confirmed malicious process using an authorized administrative procedure.

**Current implementation:** The mitigation program records a dry-run containment recommendation. Automatic process termination and network isolation are not yet implemented.

### 5. Eradication

After containment, the team will:

- Identify the source of the suspicious activity.
- Remove unauthorized files or processes.
- Review system configuration and persistence mechanisms.
- Rebuild the VM from a trusted snapshot if system integrity cannot be established.

### 6. Recovery

The recovery process uses known-good backups.

1. Confirm the malicious activity has stopped.
2. Verify the backup is trustworthy.
3. Restore the affected test files.
4. Calculate SHA-256 hashes of restored files.
5. Compare the hashes with the original backup records.
6. Confirm that the restored files are accessible.

### 7. Incident Logging

The mitigation program records incident information in an SQLite database.

The recorded information includes:

- Incident ID
- Timestamp
- Severity
- Description of suspicious activity
- Recommended containment response

### 8. Testing and Validation

The team tested the mitigation prototype on Ubuntu using four harmless sample files.

Completed tests:

- Successful backup of four files.
- Prevention of accidental backup overwriting.
- Generation of a simulated suspicious-activity alert.
- Retrieval of the recorded incident.
- Modification and restoration of a test file.
- Successful SHA-256 integrity verification.

### 9. Defense in Depth

Our planned defense combines monitoring, detection, containment, backup, recovery, and incident logging.

The objective is to reduce the impact of a successful attack even if an earlier defensive layer fails.

### 10. Limitations and Future Improvements

The current implementation does not automatically detect ransomware or terminate processes.

Future improvements include:

- Integration with `auditd` monitoring.
- Rule-based suspicious-activity detection.
- Controlled process containment after verification.
- More secure backup storage and access restrictions.
- Additional false-positive and recovery testing.

### 11. Conclusion

The mitigation component demonstrates that important test files can be backed up, restored, and verified after a simulated incident. Incident logging provides a record of suspicious activity and recommended response actions.

This prototype establishes the foundation for integration with the team's monitoring and detection components.
