"""Shared helpers for the OmniShield evaluation harnesses."""

import json
import os
from datetime import datetime

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def save_results(name: str, payload: dict) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(RESULTS_DIR, f"{name}_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    # Also write/overwrite a "latest" copy for easy reference.
    latest = os.path.join(RESULTS_DIR, f"{name}_latest.json")
    with open(latest, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return path


def print_table(rows: list[dict], columns: list[str]) -> None:
    widths = {c: max(len(c), *(len(f"{r.get(c, '')}") for r in rows)) for c in columns}
    header = " | ".join(c.ljust(widths[c]) for c in columns)
    print(header)
    print("-" * len(header))
    for r in rows:
        print(" | ".join(f"{r.get(c, '')}".ljust(widths[c]) for c in columns))
