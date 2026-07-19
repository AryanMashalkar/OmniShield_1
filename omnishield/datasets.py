"""Network traffic datasets (NSL-KDD).

Provides three things:

1. ``load_normal_traffic_samples`` — (protocol, byte_count) tuples used for the
   simulated live background traffic (original behaviour).
2. ``load_labeled_records`` — full labeled records (normal + attacks) used by
   the replay stream mode and the detection evaluation harness.
3. ``load_feature_matrix`` — a numeric feature matrix + binary labels
   (0 = normal, 1 = attack) for the ML anomaly-detection baselines.

NSL-KDD is a well-known published intrusion-detection benchmark (a refined
KDDCup'99). The cached CSV has 42 columns, label at index 41, no header.
"""

import csv
import io
import os
import random
import urllib.request

NSL_KDD_URL = (
    "https://raw.githubusercontent.com/Mamcose/"
    "NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
)
NSL_KDD_CACHE_FILE = "nsl_kdd_cache.csv"
MAX_PACKET_BYTES_DISPLAY = 200_000

# Standard NSL-KDD column layout (42 cols; label at index 41).
PROTOCOL_COL = 1
SRC_BYTES_COL = 4
DST_BYTES_COL = 5
LABEL_COL = 41

# Numeric continuous feature columns used for the ML baselines. We skip the
# three categorical columns (protocol_type, service, flag) and the label.
NUMERIC_FEATURE_COLS = [
    0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
]


def fetch_nsl_kdd_raw() -> str:
    if os.path.exists(NSL_KDD_CACHE_FILE):
        with open(NSL_KDD_CACHE_FILE, "r", encoding="utf-8") as f:
            return f.read()

    print("[OmniShield] Downloading NSL-KDD dataset (first run only)...")
    with urllib.request.urlopen(NSL_KDD_URL, timeout=60) as response:
        raw = response.read().decode("utf-8", errors="ignore")

    with open(NSL_KDD_CACHE_FILE, "w", encoding="utf-8") as f:
        f.write(raw)

    return raw


def _iter_rows():
    raw = fetch_nsl_kdd_raw()
    for row in csv.reader(io.StringIO(raw)):
        if len(row) < 42:
            continue
        yield row


def load_normal_traffic_samples() -> list[tuple[str, int]]:
    """(protocol, byte_count) for 'normal'-labeled records only."""
    try:
        rows = list(_iter_rows())
    except Exception as e:  # pragma: no cover - network / IO failure path
        print(f"[WARNING] Could not fetch NSL-KDD ({e}). Using synthetic packet sizes.")
        return []

    samples: list[tuple[str, int]] = []
    for row in rows:
        if row[LABEL_COL] != "normal":
            continue
        try:
            total = int(row[SRC_BYTES_COL]) + int(row[DST_BYTES_COL])
        except ValueError:
            continue
        if total <= 0:
            continue
        samples.append((row[PROTOCOL_COL].upper(), total))

    if not samples:
        print("[WARNING] Parsed 0 usable NSL-KDD samples. Using synthetic packet sizes.")
        return []

    print(f"[OmniShield] Loaded {len(samples)} normal NSL-KDD traffic samples.")
    return samples


def load_labeled_records(limit: int | None = None, shuffle: bool = False) -> list[dict]:
    """Full labeled records (normal + attacks) for replay / evaluation.

    Each record: {protocol, src_ip, dst_ip, bytes, label, is_attack, attack_type}.
    Source/destination IPs are synthetic (NSL-KDD has none) but deterministic
    per record so a replay looks coherent.
    """
    rows = list(_iter_rows())
    if shuffle:
        random.shuffle(rows)
    if limit is not None:
        rows = rows[:limit]

    records: list[dict] = []
    for i, row in enumerate(rows):
        try:
            total = int(row[SRC_BYTES_COL]) + int(row[DST_BYTES_COL])
        except ValueError:
            continue
        label = row[LABEL_COL]
        is_attack = label != "normal"
        records.append(
            {
                "protocol": row[PROTOCOL_COL].upper(),
                "src_ip": f"192.168.1.{10 + (i % 240)}",
                "dst_ip": f"10.0.0.{1 + (i % 250)}" if not is_attack
                else f"185.199.{i % 255}.{(i * 7) % 255}",
                "bytes": max(total, 0),
                "label": label,
                "is_attack": is_attack,
                "attack_type": None if not is_attack else label,
            }
        )
    return records


def load_feature_matrix(limit: int | None = None):
    """Return (X, y, byte_signal) as numpy arrays.

    X          : (n, d) numeric feature matrix for ML baselines.
    y          : (n,) binary labels — 0 normal, 1 attack.
    byte_signal: (n,) src+dst byte totals — the univariate signal used by the
                 project's streaming z-score / EWMA detectors.
    """
    import numpy as np

    rows = list(_iter_rows())
    if limit is not None:
        rows = rows[:limit]

    feats: list[list[float]] = []
    labels: list[int] = []
    bytes_sig: list[float] = []
    for row in rows:
        try:
            vec = [float(row[c]) for c in NUMERIC_FEATURE_COLS]
        except ValueError:
            continue
        feats.append(vec)
        labels.append(0 if row[LABEL_COL] == "normal" else 1)
        bytes_sig.append(float(row[SRC_BYTES_COL]) + float(row[DST_BYTES_COL]))

    return (
        np.asarray(feats, dtype=float),
        np.asarray(labels, dtype=int),
        np.asarray(bytes_sig, dtype=float),
    )


def sample_packet(samples: list[tuple[str, int]]) -> tuple[str, int]:
    """One simulated background packet (protocol, bytes)."""
    if samples:
        protocol, total = random.choice(samples)
        return protocol, min(total, MAX_PACKET_BYTES_DISPLAY)
    return random.choice(["TCP", "UDP", "ICMP"]), random.randint(100, 5000)
