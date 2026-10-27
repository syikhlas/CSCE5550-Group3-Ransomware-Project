
#!/usr/bin/env python3
"""Forward detection alerts to the mitigation program."""

import argparse
import subprocess
import sys
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Connect detection alerts to mitigation"
)

parser.add_argument("--reason", required=True)
parser.add_argument("--source", default="auditd-detector")
parser.add_argument("--pid", type=int)

args = parser.parse_args()

# Prepare incident information
reason = f"{args.source}: {args.reason}"

if args.pid is not None:
    reason += f" | PID: {args.pid}"

# Call the existing mitigation system
mitigation_script = Path(__file__).with_name("mitigate.py")

result = subprocess.run(
    [
        sys.executable,
        str(mitigation_script),
        "alert",
        "--reason",
        reason
    ],
    check=False
)

sys.exit(result.returncode)

