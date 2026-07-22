"""CIC-IDS-2017 dataset adapter (Canadian Institute for Cybersecurity).

The current gold-standard IDS benchmark: modern attacks (DDoS, PortScan, Bot,
Infiltration, Web attacks, FTP/SSH brute force, Heartbleed) over modern
background traffic. Targets the flow-feature CSVs (the "MachineLearningCVE"
export, ~79 columns). Gated multi-GB download, so it is not bundled; point
``OMNISHIELD_CIC_CSV`` at a CSV and set ``OMNISHIELD_DATASET=cic_ids``.

Two well-known CIC-IDS-2017 quirks are handled here:
  * Header names carry **leading spaces** (" Label", " Flow Duration", ...) —
    keys are stripped on read.
  * ``Flow Bytes/s`` / ``Flow Packets/s`` contain ``Infinity`` / ``NaN`` —
    coerced to 0.0 by ``_num`` so the ML models don't choke.

Exposes the same adapter interface as the other datasets.
"""

import csv
import math
import os
import random

from .config import settings

DATASET_NAME = "CIC-IDS-2017"
MAX_PACKET_BYTES_DISPLAY = 200_000

LABEL_COL = "Label"

# Canonical numeric feature order for the MachineLearningCVE export (78 numeric
# columns; only "Label" is non-numeric). Fixed here so the byte-signal indices
# are stable even before the CSV is present; missing columns read as 0.
CANONICAL_NUMERIC_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

_SRC_BYTES_COL = "Total Length of Fwd Packets"
_DST_BYTES_COL = "Total Length of Bwd Packets"
SRC_BYTES_FEATURE_IDX = CANONICAL_NUMERIC_COLS.index(_SRC_BYTES_COL)
DST_BYTES_FEATURE_IDX = CANONICAL_NUMERIC_COLS.index(_DST_BYTES_COL)

# Behavioural English used in replayed-attack descriptions — steers MITRE RAG
# attribution toward the right technique.
CATEGORY_PHRASE = {
    "dos": "a denial-of-service / DDoS flood",
    "probe": "network port scanning and reconnaissance",
    "botnet": "botnet command-and-control beaconing",
    "infiltration": "post-compromise host infiltration and lateral movement",
    "bruteforce": "brute-force credential guessing against a login service (FTP/SSH)",
    "webattack": "a web application attack (SQL injection, XSS, or brute force)",
    "heartbleed": "exploitation of a public-facing service vulnerability (Heartbleed)",
    "unknown": "anomalous behaviour deviating from baseline",
}

# Reference mapping (category -> representative MITRE technique) for docs/UX.
MITRE_HINTS = {
    "dos": "T1498", "probe": "T1046", "botnet": "T1071", "infiltration": "T1210",
    "bruteforce": "T1110", "webattack": "T1190", "heartbleed": "T1190",
}


def attack_category(label: str) -> str:
    """Map a CIC-IDS-2017 label to an internal category (robust to the en-dash /
    Windows-1252 encoding used in the 'Web Attack' labels)."""
    label_str = (label or "").strip().lower()
    if label_str in ("", "benign"):
        return "unknown"
    if label_str.startswith("web attack"):
        return "webattack"
    if label_str.startswith("dos") or label_str == "ddos":
        return "dos"
    if "patator" in label_str:
        return "bruteforce"
    if label_str == "portscan":
        return "probe"
    if label_str == "bot":
        return "botnet"
    if label_str == "infiltration":
        return "infiltration"
    if label_str == "heartbleed":
        return "heartbleed"
    return "unknown"


def _csv_path(path=None) -> str:
    return path or settings.cic_csv


def is_available() -> bool:
    return os.path.exists(_csv_path())


def _num(value) -> float:
    """Coerce to float; CIC's Infinity / NaN / blanks become 0.0."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) else 0.0


def _read_rows(path=None, limit=None):
    p = _csv_path(path)
    if not os.path.exists(p):
        raise FileNotFoundError(
            f"CIC-IDS-2017 CSV not found at '{p}'. Download the MachineLearningCVE "
            "flow CSVs and set OMNISHIELD_CIC_CSV to one of them."
        )
    with open(p, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for n, row in enumerate(reader):
            if limit is not None and n >= limit:
                break
            # Strip the leading/trailing whitespace CIC puts on every header key.
            yield {(k or "").strip(): v for k, v in row.items()}


def _features(row) -> list[float]:
    return [_num(row.get(c)) for c in CANONICAL_NUMERIC_COLS]


def _label(row) -> str:
    return (row.get(LABEL_COL) or "").strip()


def _is_attack(row) -> bool:
    return _label(row).upper() not in ("", "BENIGN")


def load_feature_matrix(limit: int | None = None):
    """Return (X, y, byte_signal) as numpy arrays."""
    import numpy as np

    feats: list[list[float]] = []
    labels: list[int] = []
    bytes_sig: list[float] = []
    for row in _read_rows(limit=limit):
        feats.append(_features(row))
        labels.append(1 if _is_attack(row) else 0)
        bytes_sig.append(_num(row.get(_SRC_BYTES_COL)) + _num(row.get(_DST_BYTES_COL)))

    return (
        np.asarray(feats, dtype=float),
        np.asarray(labels, dtype=int),
        np.asarray(bytes_sig, dtype=float),
    )


def load_labeled_records(limit: int | None = None, shuffle: bool = False) -> list[dict]:
    """Full labeled records (normal + attacks) for replay / evaluation."""
    rows = list(_read_rows(limit=None))
    if shuffle:
        random.shuffle(rows)
    if limit is not None:
        rows = rows[:limit]

    records: list[dict] = []
    for i, row in enumerate(rows):
        is_attack = _is_attack(row)
        label = _label(row) or "BENIGN"
        total = int(_num(row.get(_SRC_BYTES_COL)) + _num(row.get(_DST_BYTES_COL)))
        # The MachineLearningCVE export has no protocol column; infer a coarse one.
        dport = int(_num(row.get("Destination Port")))
        proto = "UDP" if dport in (53, 123, 161, 500) else "TCP"
        records.append(
            {
                "protocol": proto,
                "src_ip": f"192.168.1.{10 + (i % 240)}",
                "dst_ip": f"10.0.0.{1 + (i % 250)}" if not is_attack
                else f"185.199.{i % 255}.{(i * 7) % 255}",
                "bytes": max(total, 0),
                "features": _features(row),
                "label": "normal" if not is_attack else label,
                "is_attack": is_attack,
                "attack_type": None if not is_attack else label,
                "attack_category": None if not is_attack else attack_category(label),
            }
        )
    return records


def load_normal_feature_samples() -> list[dict]:
    """Benign records with full feature vectors for the simulate stream."""
    try:
        rows = list(_read_rows(limit=None))
    except Exception as e:  # pragma: no cover - missing-file path
        print(f"[WARNING] Could not read CIC-IDS-2017 ({e}). Simulate stream loses features.")
        return []

    samples: list[dict] = []
    for row in rows:
        if _is_attack(row):
            continue
        total = int(_num(row.get(_SRC_BYTES_COL)) + _num(row.get(_DST_BYTES_COL)))
        if total <= 0:
            continue
        dport = int(_num(row.get("Destination Port")))
        proto = "UDP" if dport in (53, 123, 161, 500) else "TCP"
        samples.append({"protocol": proto, "bytes": total, "features": _features(row)})
    return samples


def sample_feature_packet(samples: list[dict]) -> tuple[str, int, list[float] | None]:
    """One simulated normal background packet (protocol, display_bytes, features)."""
    if samples:
        rec = random.choice(samples)
        return rec["protocol"], min(rec["bytes"], MAX_PACKET_BYTES_DISPLAY), rec["features"]
    return random.choice(["TCP", "UDP", "ICMP"]), random.randint(100, 5000), None
