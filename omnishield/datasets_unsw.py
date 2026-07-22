"""UNSW-NB15 dataset adapter (modern; Australian Centre for Cyber Security).

Targets the **partitioned CSV set** (``UNSW_NB15_training-set.csv`` /
``UNSW_NB15_testing-set.csv``) — the clean, headered, 45-column version most
people use (~257k rows total). It is a *gated* download, so it is not bundled;
point ``OMNISHIELD_UNSW_CSV`` at the file and set ``OMNISHIELD_DATASET=unsw_nb15``.

Exposes the same adapter interface as ``datasets_nsl`` so the detection
pipeline, live stream and eval harness are dataset-agnostic.

Schema highlights:
  * ``label``      : 0 = normal, 1 = attack.
  * ``attack_cat`` : Normal / Generic / Exploits / Fuzzers / DoS /
                     Reconnaissance / Analysis / Backdoor / Shellcode / Worms.
  * ``sbytes`` / ``dbytes`` : source/dest byte counts -> the univariate signal.
"""

import csv
import math
import os
import random

from .config import settings

DATASET_NAME = "UNSW-NB15"
MAX_PACKET_BYTES_DISPLAY = 200_000

# Categorical / identifier / label columns excluded from the numeric matrix.
_EXCLUDE = {"id", "proto", "service", "state", "attack_cat", "label"}

# Canonical numeric feature order for the partitioned UNSW-NB15 set. Fixed here
# (independent of the file) so the byte-signal indices below are stable even
# before the CSV is present. Missing columns simply read as 0.
CANONICAL_NUMERIC_COLS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean",
    "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
    "ct_srv_dst", "is_sm_ips_ports",
]

SRC_BYTES_FEATURE_IDX = CANONICAL_NUMERIC_COLS.index("sbytes")
DST_BYTES_FEATURE_IDX = CANONICAL_NUMERIC_COLS.index("dbytes")

# UNSW attack_cat -> internal category (shared vocabulary with the phrase map).
UNSW_CATEGORY = {
    "dos": "dos",
    "reconnaissance": "probe",
    "analysis": "analysis",
    "backdoor": "backdoor", "backdoors": "backdoor",
    "exploits": "exploit",
    "fuzzers": "fuzzing",
    "generic": "generic",
    "shellcode": "shellcode",
    "worms": "worm",
}

# Behavioural English used in replayed-attack descriptions — steers MITRE RAG
# attribution toward the right technique (the modern win over NSL-KDD labels).
CATEGORY_PHRASE = {
    "dos": "a denial-of-service flood",
    "probe": "network reconnaissance and host/port scanning",
    "analysis": "port scanning and traffic analysis reconnaissance",
    "backdoor": "a backdoor establishing persistent remote access",
    "exploit": "exploitation of a software vulnerability for code execution",
    "fuzzing": "protocol fuzzing probing a service for vulnerabilities",
    "generic": "a known-signature attack against a block cipher / service",
    "shellcode": "shellcode delivered through a memory-corruption exploit",
    "worm": "a self-propagating worm spreading between hosts",
    "unknown": "anomalous behaviour deviating from baseline",
}

# Reference mapping (category -> a representative MITRE technique) for docs/UX.
MITRE_HINTS = {
    "dos": "T1498", "probe": "T1046", "analysis": "T1046", "backdoor": "T1505",
    "exploit": "T1203", "fuzzing": "T1595", "generic": "T1600",
    "shellcode": "T1059", "worm": "T1210",
}


def attack_category(label: str) -> str:
    return UNSW_CATEGORY.get((label or "").strip().lower(), "unknown")


def _csv_path(path=None) -> str:
    return path or settings.unsw_csv


def is_available() -> bool:
    return os.path.exists(_csv_path())


def _num(value) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) else 0.0


def _read_rows(path=None, limit=None):
    p = _csv_path(path)
    if not os.path.exists(p):
        raise FileNotFoundError(
            f"UNSW-NB15 CSV not found at '{p}'. Download the partitioned set "
            "(UNSW_NB15_training-set.csv) and set OMNISHIELD_UNSW_CSV to its path."
        )
    with open(p, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for n, row in enumerate(reader):
            if limit is not None and n >= limit:
                break
            # Normalise header keys (strip stray whitespace).
            yield {(k or "").strip(): v for k, v in row.items()}


def _features(row) -> list[float]:
    return [_num(row.get(c)) for c in CANONICAL_NUMERIC_COLS]


def _is_attack(row) -> bool:
    label = (row.get("label") or "").strip()
    if label in ("0", "1"):
        return label == "1"
    # Fall back to attack_cat if the label column is absent/blank.
    return (row.get("attack_cat") or "").strip().lower() not in ("", "normal")


def load_feature_matrix(limit: int | None = None):
    """Return (X, y, byte_signal) as numpy arrays."""
    import numpy as np

    feats: list[list[float]] = []
    labels: list[int] = []
    bytes_sig: list[float] = []
    for row in _read_rows(limit=limit):
        feats.append(_features(row))
        labels.append(1 if _is_attack(row) else 0)
        bytes_sig.append(_num(row.get("sbytes")) + _num(row.get("dbytes")))

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
        attack_cat = (row.get("attack_cat") or "").strip() or "Normal"
        total = int(_num(row.get("sbytes")) + _num(row.get("dbytes")))
        records.append(
            {
                "protocol": (row.get("proto") or "TCP").upper(),
                "src_ip": f"192.168.1.{10 + (i % 240)}",
                "dst_ip": f"10.0.0.{1 + (i % 250)}" if not is_attack
                else f"185.199.{i % 255}.{(i * 7) % 255}",
                "bytes": max(total, 0),
                "features": _features(row),
                "label": "normal" if not is_attack else attack_cat,
                "is_attack": is_attack,
                "attack_type": None if not is_attack else attack_cat,
                "attack_category": None if not is_attack else attack_category(attack_cat),
            }
        )
    return records


def load_normal_feature_samples() -> list[dict]:
    """Normal-labeled records with full feature vectors for the simulate stream."""
    try:
        rows = list(_read_rows(limit=None))
    except Exception as e:  # pragma: no cover - missing-file path
        print(f"[WARNING] Could not read UNSW-NB15 ({e}). Simulate stream loses features.")
        return []

    samples: list[dict] = []
    for row in rows:
        if _is_attack(row):
            continue
        total = int(_num(row.get("sbytes")) + _num(row.get("dbytes")))
        if total <= 0:
            continue
        samples.append(
            {"protocol": (row.get("proto") or "TCP").upper(), "bytes": total, "features": _features(row)}
        )
    return samples


def sample_feature_packet(samples: list[dict]) -> tuple[str, int, list[float] | None]:
    """One simulated normal background packet (protocol, display_bytes, features)."""
    if samples:
        rec = random.choice(samples)
        return rec["protocol"], min(rec["bytes"], MAX_PACKET_BYTES_DISPLAY), rec["features"]
    return random.choice(["TCP", "UDP", "ICMP"]), random.randint(100, 5000), None
