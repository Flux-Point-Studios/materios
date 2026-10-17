"""Generate FRAME fits bounded by every measured component median."""
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def main():
    samples_path = ROOT / "pallets/orinq-receipts/benchmarking/attestation-samples.json"
    output = ROOT / "pallets/orinq-receipts/src/attestation_weights.rs"
    subprocess.run([
        "frame-omni-bencher", "v1", "benchmark", "pallet",
        "--json-input", str(samples_path), "--output-analysis", "max",
        "--output", str(output), "--template",
        str(ROOT / "pallets/orinq-receipts/benchmarking/attestation-weight.hbs"),
    ], check=True, stdout=subprocess.DEVNULL)
    generated = output.read_text()
    for sample in json.loads(samples_path.read_text()):
        name = sample["benchmark"]
        function = re.search(rf"pub fn {name}<[^\n]+[\s\S]*?\n}}", generated)
        assert function is not None, name
        body = function[0]
        base_match = re.search(r"Weight::from_parts\(([\d_]+), proof\)", body)
        assert base_match is not None
        base = int(base_match[1].replace("_", ""))
        slope_match = re.search(r"Weight::from_parts\(([\d_]+), 0\)", body)
        slope = int(slope_match[1].replace("_", "")) if slope_match else 0
        groups = defaultdict(list)
        for row in sample["time_results"]:
            groups[dict(row["components"]).get("n", 0)].append(row["extrinsic_time"] * 1_000)
        medians = {n: sorted(times)[len(times) // 2] for n, times in groups.items()}
        if 0 in medians and len(medians) > 1:
            base = max(base, medians[0])
            slope = max(slope, max(-(-(time - base) // n) for n, time in medians.items() if n))
        else:
            base = max(base, max(time - slope * n for n, time in medians.items()))
        replacement = body.replace(base_match[0], f"Weight::from_parts({base:_}, proof)", 1)
        if slope_match:
            replacement = replacement.replace(slope_match[0], f"Weight::from_parts({slope:_}, 0)", 1)
        generated = generated.replace(body, replacement, 1)
    output.write_text(generated)

    samples = json.loads((ROOT / "pallets/motra/benchmarking/reconciliation-samples.json").read_text())
    fee = next(sample for sample in samples if sample["benchmark"] == "fee_path")
    time = max(row["extrinsic_time"] for row in fee["time_results"]) * 1_000
    reads = max(row["reads"] for row in fee["db_results"])
    writes = max(row["writes"] for row in fee["db_results"])
    path = ROOT / "pallets/motra/src/reconciliation_weights.rs"
    head, tail = path.read_text().split("pub fn fee_path", 1)
    tail, times = re.subn(r"Weight::from_parts\([\d_]+, proof\)", f"Weight::from_parts({time:_}, proof)", tail, count=1)
    tail, read_counts = re.subn(r"db.reads\(\d+\)", f"db.reads({reads})", tail, count=1)
    tail, write_counts = re.subn(r"db.writes\(\d+\)", f"db.writes({writes})", tail, count=1)
    assert (times, read_counts, write_counts) == (1, 1, 1)
    path.write_text(head + "pub fn fee_path" + tail)
    subprocess.run(["rustfmt", "--edition", "2021", str(output), str(path)], check=True)


if __name__ == "__main__":
    main()
