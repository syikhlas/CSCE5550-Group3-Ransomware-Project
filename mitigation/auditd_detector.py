
#!/usr/bin/env python3
"""Demo detector for auditd-style file modification events."""

import argparse
import subprocess
import sys
from pathlib import Path

THRESHOLD = 3


def detect(log_file):
    modified_files = set()

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            # Simplified audit event format for testing only:
            # type=FILE_CHANGE path=/path/to/file
            if "type=FILE_CHANGE" not in line:
                continue

            for field in line.split():
                if field.startswith("path="):
                    modified_files.add(field.removeprefix("path="))

    print(f"Detected modifications to {len(modified_files)} unique files")

    if len(modified_files) >= THRESHOLD:
        print("WARNING: Suspicious bulk file modifications!")

        bridge = Path(__file__).with_name("auditd_bridge.py")

        result = subprocess.run(
            [
                sys.executable,
                str(bridge),
                "--reason",
                f"{len(modified_files)} files modified",
                "--source",
                "auditd-demo-detector",
            ],
            check=False,
        )
        return result.returncode

    print("No suspicious bulk modification pattern detected.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("log_file", help="Path to sample audit log")
    args = parser.parse_args()

    sys.exit(detect(args.log_file))
