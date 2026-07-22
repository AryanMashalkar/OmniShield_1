"""NSL-KDD dataset adapter (default, offline-cached).

NSL-KDD is a refined KDDCup'99 benchmark. The cached CSV has 42 columns, label
at index 41, no header. This module is one of the pluggable dataset adapters
behind ``omnishield.datasets`` — it exposes the canonical adapter interface:

    DATASET_NAME
    SRC_BYTES_FEATURE_IDX / DST_BYTES_FEATURE_IDX
    CATEGORY_PHRASE
    attack_category(label)
    load_feature_matrix(limit)
    load_labeled_records(limit, shuffle)
    load_normal_feature_samples()
    sample_feature_packet(samples)
"""

import csv
import io
import os
import random
import urllib.request

DATASET_NAME = "NSL-KDD"

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

# Positions of the src/dst byte columns *within* the assembled feature vector
# (NUMERIC_FEATURE_COLS), so the hybrid detector can reconstruct the univariate
# byte signal from a feature row without hard-coding magic indices.
SRC_BYTES_FEATURE_IDX = NUMERIC_FEATURE_COLS.index(SRC_BYTES_COL)
DST_BYTES_FEATURE_IDX = NUMERIC_FEATURE_COLS.index(DST_BYTES_COL)

# NSL-KDD attack labels grouped into the four canonical families. Used to give
# replayed attacks a meaningful, category-correct description so downstream
# MITRE attribution isn't misled (e.g. calling a 0-byte DoS flood "exfiltration").
NSL_KDD_ATTACK_CATEGORY = {
    # Denial of Service
    "neptune": "dos", "smurf": "dos", "back": "dos", "teardrop": "dos",
    "pod": "dos", "land": "dos", "apache2": "dos", "processtable": "dos",
    "mailbomb": "dos", "udpstorm": "dos", "worm": "dos",
    # Probe / reconnaissance
    "satan": "probe", "ipsweep": "probe", "portsweep": "probe", "nmap": "probe",
    "mscan": "probe", "saint": "probe",
    # Remote-to-Local
    "guess_passwd": "r2l", "ftp_write": "r2l", "imap": "r2l", "phf": "r2l",
    "multihop": "r2l", "warezmaster": "r2l", "warezclient": "r2l", "spy": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "snmpguess": "r2l", "snmpgetattack": "r2l",
    "httptunnel": "r2l", "sendmail": "r2l", "named": "r2l",
    # User-to-Root (privilege escalation)
    "buffer_overflow": "u2r", "loadmodule": "u2r", "rootkit": "u2r", "perl": "u2r",
    "sqlattack": "u2r", "xterm": "u2r", "ps": "u2r",
}

CATEGORY_PHRASE = {
    "dos": "a denial-of-service flood",
    "probe": "network scanning / reconnaissance",
    "r2l": "a remote-to-local intrusion attempt",
    "u2r": "a privilege-escalation exploit",
    "unknown": "anomalous behaviour deviating from baseline",
}


def attack_category(label: str) -> str:
    return NSL_KDD_ATTACK_CATEGORY.get((label or "").lower(), "unknown")


def is_available() -> bool:
    """NSL-KDD auto-downloads and caches on first use, so it is always usable."""
    return True


def _row_features(row) -> list[float] | None:
    """Assemble the numeric feature vector for one NSL-KDD row (or None)."""
    try:
        return [float(row[c]) for c in NUMERIC_FEATURE_COLS]
    except (ValueError, IndexError):
        return None


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


def load_normal_feature_samples() -> list[dict]:
    """Normal-labeled records with full feature vectors for the simulate stream."""
    try:
        rows = list(_iter_rows())
    except Exception as e:  # pragma: no cover - network / IO failure path
        print(f"[WARNING] Could not fetch NSL-KDD ({e}). Simulate stream loses features.")
        return []

    samples: list[dict] = []
    for row in rows:
        if row[LABEL_COL] != "normal":
            continue
        feats = _row_features(row)
        if feats is None:
            continue
        total = int(feats[SRC_BYTES_FEATURE_IDX]) + int(feats[DST_BYTES_FEATURE_IDX])
        if total <= 0:
            continue
        samples.append({"protocol": row[PROTOCOL_COL].upper(), "bytes": total, "features": feats})

    return samples


def sample_feature_packet(samples: list[dict]) -> tuple[str, int, list[float] | None]:
    """One simulated normal background packet (protocol, display_bytes, features)."""
    if samples:
        rec = random.choice(samples)
        return rec["protocol"], min(rec["bytes"], MAX_PACKET_BYTES_DISPLAY), rec["features"]
    return random.choice(["TCP", "UDP", "ICMP"]), random.randint(100, 5000), None


def load_labeled_records(limit: int | None = None, shuffle: bool = False) -> list[dict]:
    """Full labeled records (normal + attacks) for replay / evaluation."""
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
                "features": _row_features(row),
                "label": label,
                "is_attack": is_attack,
                "attack_type": None if not is_attack else label,
                "attack_category": None if not is_attack else attack_category(label),
            }
        )
    return records


def load_feature_matrix(limit: int | None = None):
    """Return (X, y, byte_signal) as numpy arrays."""
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
