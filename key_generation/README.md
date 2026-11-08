# Key Generation — CSCE 5550 Group 3

Attacker-side utility (run on the **Kali VM**): generates the RSA-2048 key pair
used by the hybrid-encryption scheme and prints everything needed to wire it
into the encryptor and decryptor.

## Usage

```bash
python3 keygen.py
```

Requires Python 3 and [pycryptodome](https://pycryptodome.readthedocs.io/)
(`pip install pycryptodome`).

## What it produces

- **`ransom_private.pem`** — the RSA secret key, saved in the current directory.
  It **never leaves the attacker machine** until the simulated ransom is paid;
  then the attacker transfers it (with the decryptor) to the victim, exactly as
  the project description requires ("the decryption component is supposed to be
  transferred to the victim once the ransom is paid").
- **Paste-ready `PUBLIC_KEY_PEM` block** (stdout) — copy into the
  `PUBLIC_KEY_PEM` constant of `encryption_decryption/encryption.py`. The
  public key travels with the ransomware, like real families embed it in the
  binary; it is useless to the victim because only the secret key can unwrap
  the AES session key.
- **Paste-ready `PRIVATE_KEY_PEM` block** (stdout) — copy into the
  `PRIVATE_KEY_PEM` constant of `encryption_decryption/decryption.py` if you
  want a self-contained decryptor (the flow used in our demo).
- **SHA-256 fingerprints** of both keys — used to confirm that the key embedded
  in the encryptor/decryptor matches the generated pair (sanity check before
  each experiment run).

The script also reloads the saved private key from disk and asserts that the
exported public key matches, so a truncated/corrupted PEM is caught immediately.

## Key-management model

| Key | Where it lives | When the victim gets it |
|---|---|---|
| RSA public key (2048-bit) | Embedded in `encryption.py` (the payload) | At infection time (it is the malware) |
| RSA private key | `ransom_private.pem` on Kali / embedded in `decryption.py` | Only after the simulated ransom payment |

## Notes

- RSA-2048 with OAEP is the modern practical minimum; RSA is used **only** to
  wrap the 32-byte AES session key (~190-byte payload limit per operation),
  while AES-256-GCM does the bulk file encryption.
- The private key is exported **unencrypted** (no passphrase) for lab
  simplicity; a real operator would protect it with a passphrase
  (`export_key(passphrase=..., pkcs=8, protection=...)`).
- If you regenerate the pair, you must re-paste **both** blocks (public key into
  the encryptor, private key into the decryptor or re-send the PEM) — the
  fingerprints printed at the end make it easy to verify the match.
