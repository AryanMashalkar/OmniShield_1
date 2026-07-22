"""Incident / campaign correlation — turn a flat anomaly stream into stories.

Individually, anomalies are noise. This engine groups them **by entity (source
host)** within a time window into a single *incident*, records the sequence of
MITRE techniques attributed to that host, orders them along the ATT&CK kill
chain, and runs the Next-Move Predictor on the furthest-along stage. That is
exactly PS#7's "correlate weak signals ... map attack progression" — and it makes
the dashboard say *"host X: Discovery -> Credential Access -> Lateral Movement,
next likely Collection"* instead of showing 40 disconnected red rows.

State is in-memory and TTL-pruned (a live SOC would back this with a store).
"""

from __future__ import annotations

import time
from datetime import datetime

from .nextmove import TACTIC_ORDER, predict_next_moves

CAMPAIGN_TTL_SEC = 900  # incidents idle longer than this are pruned
_TACTIC_INDEX = {t: i for i, t in enumerate(TACTIC_ORDER)}

_campaigns: dict[str, dict] = {}


def _now() -> float:
    return time.time()


def _new(entity: str) -> dict:
    now = _now()
    return {
        "entity": entity,
        "first_seen": now,
        "last_seen": now,
        "anomaly_count": 0,
        "categories": set(),
        "techniques": [],  # [{id, name, tactic, seen}]
        "_ids": set(),
    }


def reset() -> None:
    _campaigns.clear()


def record_anomaly(entity: str, category: str | None = None) -> None:
    """A raw anomaly fired for ``entity`` (before/without attribution)."""
    c = _campaigns.setdefault(entity, _new(entity))
    c["last_seen"] = _now()
    c["anomaly_count"] += 1
    if category:
        c["categories"].add(category)


def record_attribution(entity: str, technique_id: str, technique_name: str | None) -> None:
    """A technique was attributed to ``entity`` — add it to the host's campaign."""
    tid = (technique_id or "").upper().strip()
    if not (tid.startswith("T") and tid[1:].isdigit()):
        return
    c = _campaigns.setdefault(entity, _new(entity))
    c["last_seen"] = _now()
    if tid in c["_ids"]:
        return
    c["_ids"].add(tid)
    forecast = predict_next_moves(tid)
    c["techniques"].append(
        {
            "id": tid,
            "name": technique_name or forecast.get("technique_name"),
            "tactic": forecast.get("current_tactic"),
            "seen": _now(),
        }
    )


def _prune() -> None:
    cutoff = _now() - CAMPAIGN_TTL_SEC
    for entity in [e for e, c in _campaigns.items() if c["last_seen"] < cutoff]:
        del _campaigns[entity]


def _hhmmss(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def get_campaigns(limit: int = 10) -> list[dict]:
    """Correlated incidents, richest story first (most kill-chain stages, then volume)."""
    _prune()
    out = []
    for c in _campaigns.values():
        techs = sorted(
            c["techniques"], key=lambda t: _TACTIC_INDEX.get(t["tactic"], -1)
        )
        stages = [t["tactic"] for t in techs if t["tactic"]]
        # Furthest-along technique drives the campaign-level forecast.
        forecast = None
        if techs:
            furthest = max(techs, key=lambda t: _TACTIC_INDEX.get(t["tactic"], -1))
            forecast = predict_next_moves(furthest["id"])
        out.append(
            {
                "entity": c["entity"],
                "anomaly_count": c["anomaly_count"],
                "categories": sorted(c["categories"]),
                "first_seen": _hhmmss(c["first_seen"]),
                "last_seen": _hhmmss(c["last_seen"]),
                "duration_sec": round(c["last_seen"] - c["first_seen"], 1),
                "techniques": [
                    {"id": t["id"], "name": t["name"], "tactic": t["tactic"]} for t in techs
                ],
                "stages": stages,
                "stage_span": len(set(stages)),
                "forecast": forecast,
            }
        )
    out.sort(key=lambda x: (x["stage_span"], x["anomaly_count"]), reverse=True)
    return out[:limit]
