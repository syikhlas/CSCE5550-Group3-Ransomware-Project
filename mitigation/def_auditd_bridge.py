#!/usr/bin/env python3
"""Forward detection alerts to the mitigation program.

Receives an alert from monitor.py (or manually) with the PID and the
executable path of the suspicious process and calls mitigate.py, which logs
the incident and contains (stops) the process.
"""

import argparse
import subprocess
import sys
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Connect detection alerts to mitigation"
)

parser.add_argument("--reason", required=True)
parser.add_argument("--source", default="monitor.py")
parser.add_argument("--pid", type=int)
parser.add_argument("--exe")

args = parser.parse_args()

# Prepare incident information
reason = f"{args.source}: {args.reason}"

if args.pid is not None:
    reason += f" | PID: {args.pid}"
if args.exe:
    reason += f" | exe: {args.exe}"

# Call the mitigation system, forwarding pid and exe so it can contain them
mitigation_script = Path(__file__).with_name("mitigate.py")

cmd = [sys.executable, str(mitigation_script), "alert", "--reason", reason]
if args.pid is not None:
    cmd += ["--pid", str(args.pid)]
if args.exe:
    cmd += ["--exe", args.exe]

result = subprocess.run(cmd, check=False)

sys.exit(result.returncode)
