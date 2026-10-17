import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def select(packet, work, all_phases):
    current = re.findall(r"^CURRENT_PHASE: P([0-5])$", work, re.M)
    if len(current) != 1:
        raise ValueError("WORK.md must declare exactly one CURRENT_PHASE: P0-P5")
    selected = []
    for check in packet["checks"]:
        phase = re.match(r"^Phase P([0-5])\. ", check["scope"])
        if phase is None:
            raise ValueError(f"{check['id']}: missing or unknown phase")
        if all_phases or int(phase[1]) <= int(current[0]):
            selected.append(check)
    if not selected:
        raise ValueError("no checks selected")
    return selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    packet_path = ROOT / ".fluxpoint-spec.json"
    packet_bytes = packet_path.read_bytes()
    work_bytes = (ROOT / "WORK.md").read_bytes()
    packet = json.loads(packet_bytes)
    selected = select(packet, work_bytes.decode(), args.all)
    results = []
    for check in selected:
        argv = [sys.executable if arg == "{python}" else arg for arg in check["argv"]]
        try:
            result = subprocess.run(argv, cwd=ROOT, timeout=check["timeoutSeconds"], check=False)
            code = result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"RED {check['id']}: {error}", flush=True)
            code = 1
        results.append((check["id"], "GREEN" if code == 0 else "RED"))
    if packet_path.read_bytes() != packet_bytes or (ROOT / "WORK.md").read_bytes() != work_bytes:
        raise ValueError("specification or phase changed during execution")
    print("\nPhase check report", flush=True)
    for name, status in results:
        print(f"{name}: {status}")
    selected_ids = {name for name, _ in results}
    for check in packet["checks"]:
        if check["id"] not in selected_ids:
            print(f"{check['id']}: NOT RUN ({check['scope'].split('. ', 1)[0]}; run --all)")
    return int(any(status == "RED" for _, status in results))


if __name__ == "__main__":
    sys.exit(main())
