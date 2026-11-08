# Action — Encryption / Decryption — CSCE 5550 Group 3

The attack component of the project: a hybrid-encryption ransomware tool. 
It recursively encrypts the designated `critical_abcde` directory on
the victim VM, and a decryptor restores it after the simulated ransom payment.

## Why hybrid RSA + AES

Real ransomware families use exactly this construction:

- **AES-256-GCM** encrypts every file — fast and authenticated, but symmetric,
  so the key must be protected from the victim.
- **RSA-2048-OAEP** encrypts only the 32-byte AES session key — asymmetric, so
  the victim cannot recover anything even by fully reverse-engineering the
  binary, but far too slow/size-limited for bulk data.

The AES session key is generated fresh at infection time, wrapped with the
attacker's RSA public key (embedded in the encryptor) and stored as
`key.bin.enc`. The RSA private key never touches the victim machine before the
ransom is paid — this is the "decryption component is transferred to the victim
once the ransom is paid" requirement of the project description.

## Files

- `encryption.py` — the ransomware encryptor (runs on the victim)
- `decryption.py` — the decryptor (delivered after payment; the RSA private key
  is embedded in `PRIVATE_KEY_PEM`, or can be passed as a PEM file argument)

## Requirements

- Python 3, [pycryptodome](https://pycryptodome.readthedocs.io/): `pip install pycryptodome`

## Usage

**Encrypt (attack):**

```bash
python3 encryption.py /home/osboxes/Desktop/critical_abcde
# or explicitly: python3 encryption.py <target_dir> --euid abcde
```

**Decrypt (after the simulated payment):**

```bash
python3 decryption.py /home/osboxes/Desktop/critical_abcde
# or with the key file sent by the attacker:
python3 decryption.py /home/osboxes/Desktop/critical_abcde ransom_private.pem
```

## What the encryptor does

1. **Scope guard** — refuses to run unless the target directory is named exactly
   `critical_<EUID>` (`critical_abcde`). Presented in the report as deliberate
   target confinement; in practice it guarantees the tool never runs outside the
   designated lab directory.
2. Generates a fresh random AES-256 session key.
3. Records a plaintext **integrity manifest** (`.integrity_manifest.json`) with
   the SHA-256 of every file *before* encryption (lab verification aid — a real
   ransomware would not leave one behind).
4. Recursively walks the tree; for each file: fresh random 96-bit GCM nonce,
   AES-256-GCM encryption, then writes
   `MAGIC(8) | NONCE(12) | TAG(16) | CIPHERTEXT` to `<name>.locked_abcde` and
   deletes the plaintext original. Files already carrying the `.locked_abcde`
   extension and the tool's own artifacts are skipped (no double encryption).
5. Wraps the session key with the RSA public key (RSA-OAEP) into `key.bin.enc`.
6. Drops the ransom note `README_RESTORE.txt` with the victim ID and payment
   instructions (pointing at the Kali VM's lab address).

## What the decryptor does

1. Loads the RSA private key (embedded or from the file the attacker sent).
2. RSA-OAEP unwraps `key.bin.enc` to recover the AES session key.
3. Finds every `*.locked_abcde` file, decrypts it (the GCM tag verifies each
   file was not tampered with), strips the extension and restores the original
   name. Files that fail are left in place and reported.
4. Verifies the restored tree against the integrity manifest (SHA-256 per file).
5. Unconditionally removes `key.bin.enc`, `README_RESTORE.txt` and the manifest,
   and reports PASS/FAIL for the whole recovery.

## Security details implemented correctly

- **RSA-OAEP padding**.
- **Unique random nonce per file** — GCM nonce reuse with the same key is
  catastrophic; each file gets a fresh 96-bit nonce.
- **Magic-byte header** (`CRLOCK1!`) so the decryptor only processes its own
  files and double encryption is impossible.
- **Authenticated encryption** — GCM tags make tampered/corrupted ciphertext
  fail loudly instead of producing garbage.

