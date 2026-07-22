"""Prepare real CIC-IDS-2017 data for OmniShield.

The CIC-IDS-2017 "MachineLearningCVE" release ships as 8 per-day CSVs. This
merges them (or a single file) into one CSV that OmniShield's `cic_ids` adapter
reads directly, reports the class distribution, and prints the exact commands to
benchmark + demo on real modern traffic.

Usage:
    # after downloading MachineLearningCVE/ from https://www.unb.ca/cic/datasets/ids-2017.html
    python scripts/prepare_cic.py path\\to\\MachineLearningCVE
    python scripts/prepare_cic.py path\\to\\Wednesday-workingHours.pcap_ISCX.csv --out cic_ids2017.csv
    python scripts/prepare_cic.py path\\to\\MachineLearningCVE --per-class 20000   # balance/cap
"""

import argparse
import csv
import glob
import os
from collections import Counter


def _label_key(fieldnames):
    for name in fieldnames:
        if (name or "").strip().lower() == "label":
            return name
    return None


def main():
    ap = argparse.ArgumentParser(description="Merge CIC-IDS-2017 CSV(s) for OmniShield.")
    ap.add_argument("input", help="A CIC CSV file or a directory of them.")
    ap.add_argument("--out", default="cic_ids2017.csv", help="Output CSV path.")
    ap.add_argument("--limit", type=int, default=0, help="Max total rows (0 = all).")
    ap.add_argument("--per-class", type=int, default=0, help="Max rows per label (0 = no cap).")
    args = ap.parse_args()

    if os.path.isdir(args.input):
        files = sorted(glob.glob(os.path.join(args.input, "*.csv")))
    else:
        files = [args.input]
    if not files:
        raise SystemExit(f"No CSV files found at '{args.input}'.")

    print(f"[prepare_cic] merging {len(files)} file(s) -> {args.out}")

    header = None
    label_key = None
    per_class = Counter()
    written = 0
    with open(args.out, "w", newline="", encoding="utf-8") as out_f:
        writer = None
        for path in files:
            with open(path, newline="", encoding="utf-8", errors="ignore") as in_f:
                reader = csv.DictReader(in_f)
                if header is None:
                    header = reader.fieldnames
                    label_key = _label_key(header)
                    writer = csv.DictWriter(out_f, fieldnames=header)
                    writer.writeheader()
                for row in reader:
                    label = (row.get(label_key) or "").strip() if label_key else "?"
                    if args.per_class and per_class[label] >= args.per_class:
                        continue
                    if args.limit and written >= args.limit:
                        break
                    writer.writerow(row)
                    per_class[label] += 1
                    written += 1
            if args.limit and written >= args.limit:
                break

    print(f"[prepare_cic] wrote {written} rows")
    print("[prepare_cic] class distribution:")
    for label, n in per_class.most_common():
        print(f"    {n:>8}  {label}")

    out_abs = os.path.abspath(args.out)
    print("\n[prepare_cic] Next steps:")
    print(f"    $env:OMNISHIELD_DATASET = 'cic_ids'")
    print(f"    $env:OMNISHIELD_CIC_CSV = '{out_abs}'")
    print("    venv\\Scripts\\python -m evaluation.eval_detection --limit 200000   # real benchmark")
    print("    venv\\Scripts\\uvicorn main:app                                    # live demo (replay mode)")


if __name__ == "__main__":
    main()
