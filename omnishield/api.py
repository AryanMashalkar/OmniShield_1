"""FastAPI application: REST + WebSocket surface for the OmniShield SOC."""

import asyncio
import random
from datetime import datetime

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import correlation, db, llm, nextmove, soar
from .config import settings
from .datasets import (
    CATEGORY_PHRASE,
    load_labeled_records,
    load_normal_feature_samples,
    sample_feature_packet,
)
from .detection import (
    baseline_window,
    entity_profiles,
    evaluate_packet,
    get_live_multivariate_detector,
)
from .detection import settings as _det_settings  # noqa: F401 (keeps window in sync)

app = FastAPI(title="OmniShield AI Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)

settings.warn_if_insecure()
db.init_db()

# Background traffic samples for the simulated stream (loaded once), now carrying
# full multivariate feature vectors so the live IsolationForest can score them.
NSL_KDD_SAMPLES = load_normal_feature_samples()
# Labeled records for the replay stream (lazy — only if replay mode is used).
_REPLAY_RECORDS: list[dict] | None = None

# Warm up the multivariate live detector at startup so the very first packets
# are scored by IsolationForest rather than paying the fit cost mid-stream.
get_live_multivariate_detector()


def verify_api_key(x_api_key: str) -> None:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ScamAnalysisRequest(BaseModel):
    transcript: str


class AnomalyAttributionRequest(BaseModel):
    anomaly_description: str
    source_ip: str
    anomaly_score: float | None = None
    bytes_transferred: float | None = None
    mode: str = "rag"  # "rag" (default) or "zeroshot"


class BlockIPRequest(BaseModel):
    target_ip: str
    # Human-in-the-loop: analyst must explicitly confirm the containment action.
    analyst_confirmed: bool = False


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/")
def health_check():
    return {
        "status": "online",
        "system": "OmniShield AI Core",
        "stream_mode": settings.stream_mode,
        "soar_requires_confirmation": settings.soar_require_confirmation,
    }


# ---------------------------------------------------------------------------
# Scam transcript analysis
# ---------------------------------------------------------------------------


@app.post("/api/analyze-scam")
async def analyze_scam(payload: ScamAnalysisRequest):
    return await asyncio.to_thread(llm.analyze_scam, payload.transcript)


# ---------------------------------------------------------------------------
# Attack attribution (RAG or zero-shot ablation)
# ---------------------------------------------------------------------------


@app.post("/api/attribute-attack")
async def attribute_attack(payload: AnomalyAttributionRequest):
    if payload.mode == "zeroshot":
        result = await asyncio.to_thread(
            llm.attribute_attack_zeroshot, payload.anomaly_description, payload.source_ip
        )
    else:
        result = await asyncio.to_thread(
            llm.attribute_attack_rag,
            payload.anomaly_description,
            payload.source_ip,
            payload.anomaly_score,
            payload.bytes_transferred,
        )
    # Agentic layer: forecast the adversary's next kill-chain stages so the SOC
    # can pre-stage containment before the next move, not after.
    tid = str(result.get("matched_technique_id", ""))
    if tid.startswith("T") and tid[1:].isdigit():
        result["next_moves"] = await asyncio.to_thread(nextmove.predict_next_moves, tid)
        # Correlation: fold this technique into the source host's campaign story.
        correlation.record_attribution(payload.source_ip, tid, result.get("technique_name"))
    return result


@app.get("/api/next-moves")
async def get_next_moves(technique_id: str, horizon: int = 2):
    """ATT&CK kill-chain forecast for a technique (the Next-Move Predictor)."""
    return await asyncio.to_thread(nextmove.predict_next_moves, technique_id, horizon)


@app.get("/api/campaigns")
async def get_campaigns(limit: int = 10):
    """Correlated incidents: anomalies grouped by host into multi-stage stories."""
    return {"campaigns": correlation.get_campaigns(limit)}


@app.get("/api/entities")
async def get_entities(limit: int = 25):
    """Learned per-entity (host/device) behavioural baselines — the UEBA profiles."""
    return {"entities": entity_profiles(limit)}


# ---------------------------------------------------------------------------
# Live network stream
# ---------------------------------------------------------------------------


# A scripted multi-stage attack from a single host, so the correlation engine
# has a coherent kill-chain story to tell in simulate mode (recon -> cred access
# -> lateral movement -> exfil). Each step carries its known technique so the
# campaign builds server-side without needing an LLM call per step.
_CAMPAIGN_HOST = "192.168.1.66"
_CAMPAIGN_STEPS = [
    {
        "bytes": 40, "technique_id": "T1046", "technique_name": "Network Service Discovery",
        "description": "Sequential connection attempts to thousands of TCP ports on internal "
        "hosts from a single source — network scanning / service discovery.",
    },
    {
        "bytes": 160, "technique_id": "T1110", "technique_name": "Brute Force",
        "description": "Hundreds of rapid failed SSH authentication attempts against an internal "
        "server — brute-force credential access.",
    },
    {
        "bytes": 5000, "technique_id": "T1021", "technique_name": "Remote Services",
        "description": "Authenticated to an internal host over SMB/RDP using the compromised "
        "credentials — lateral movement to a new system.",
    },
    {
        "bytes": 900_000_000, "technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel",
        "description": "Large outbound transfer of collected data to an external host over the "
        "established command-and-control channel — data exfiltration.",
    },
]


def _campaign_packet(counter: int) -> dict:
    step = _CAMPAIGN_STEPS[(counter // 10) % len(_CAMPAIGN_STEPS)]
    return {
        "source_ip": _CAMPAIGN_HOST,
        "destination_ip": "185.199.108.153",
        "protocol": "TCP",
        "bytes_transferred": step["bytes"],
        "features": None,
        "force_anomaly": True,  # scripted step: always an anomaly regardless of bytes
        "scripted_description": step["description"],
        "campaign_technique_id": step["technique_id"],
        "campaign_technique_name": step["technique_name"],
    }


def _simulated_packet(counter: int) -> dict:
    # Advance the scripted kill-chain campaign on a distinct cadence.
    if counter % 10 == 5 and len(baseline_window) >= settings.min_baseline_samples:
        return _campaign_packet(counter)

    inject_scripted = counter % 12 == 0 and len(baseline_window) >= settings.min_baseline_samples
    if inject_scripted:
        return {
            "source_ip": "192.168.1.45",
            "destination_ip": "185.199.108.153",
            "protocol": "TCP",
            "bytes_transferred": 4_200_000_000,
            # No NSL-KDD feature vector for this synthetic event — the z-score
            # fast path is what catches this byte-spike exfiltration.
            "features": None,
            "scripted_description": (
                "Workstation suddenly transferred 4.2GB of encrypted files to an "
                "external IP at 2:00 AM after executing a PowerShell script."
            ),
        }
    protocol, bytes_transferred, features = sample_feature_packet(NSL_KDD_SAMPLES)
    return {
        "source_ip": f"192.168.1.{random.randint(10, 50)}",
        "destination_ip": f"10.0.0.{random.randint(1, 10)}",
        "protocol": protocol,
        "bytes_transferred": bytes_transferred,
        "features": features,
        "scripted_description": None,
    }


def _replay_packet(counter: int) -> dict:
    global _REPLAY_RECORDS
    if _REPLAY_RECORDS is None:
        _REPLAY_RECORDS = load_labeled_records(shuffle=True)
    rec = _REPLAY_RECORDS[counter % len(_REPLAY_RECORDS)]
    desc = None
    if rec["is_attack"]:
        phrase = CATEGORY_PHRASE.get(rec.get("attack_category") or "unknown")
        desc = (
            f"NSL-KDD attack '{rec['attack_type']}' ({phrase}) over "
            f"{rec['protocol']}, {rec['bytes']} bytes from the source host."
        )
    return {
        "source_ip": rec["src_ip"],
        "destination_ip": rec["dst_ip"],
        "protocol": rec["protocol"],
        "bytes_transferred": rec["bytes"],
        "features": rec.get("features"),
        "scripted_description": desc,
        "ground_truth_label": rec["label"],
        "attack_category": rec.get("attack_category"),
    }


@app.websocket("/ws/network-stream")
async def network_stream(websocket: WebSocket):
    await websocket.accept()
    try:
        counter = 0
        while True:
            counter += 1
            if settings.stream_mode == "replay":
                pkt = _replay_packet(counter)
            else:
                pkt = _simulated_packet(counter)

            is_anomaly, z_score, detail = evaluate_packet(
                pkt["bytes_transferred"], pkt.get("features"), entity=pkt["source_ip"]
            )
            # Scripted kill-chain steps are anomalies by construction.
            if pkt.get("force_anomaly"):
                is_anomaly = True

            log = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "source_ip": pkt["source_ip"],
                "destination_ip": pkt["destination_ip"],
                "protocol": pkt["protocol"],
                "bytes_transferred": pkt["bytes_transferred"],
                "status": "Critical" if is_anomaly else "Normal",
                "is_anomaly": is_anomaly,
                "anomaly_score": z_score,
                # Which detector(s) fired — lets the dashboard attribute alerts.
                "detector": detail["detector"],
                "z_flag": detail["z_flag"],
                "mv_flag": detail["mv_flag"],
                "mv_score": detail["mv_score"],
                # Per-entity UEBA: which baseline scored this flow.
                "baseline_scope": detail["baseline_scope"],
            }
            if "ground_truth_label" in pkt:
                log["ground_truth_label"] = pkt["ground_truth_label"]
                log["attack_category"] = pkt.get("attack_category")
                # In replay mode we know the truth, so we can score the detector
                # live: did the flag (or non-flag) match the label?
                truth_is_attack = pkt["ground_truth_label"] != "normal"
                log["detection_correct"] = bool(is_anomaly) == truth_is_attack
            if is_anomaly:
                # Correlation: fold this anomaly into the source host's incident.
                correlation.record_anomaly(pkt["source_ip"], pkt.get("attack_category"))
                if pkt.get("campaign_technique_id"):
                    correlation.record_attribution(
                        pkt["source_ip"],
                        pkt["campaign_technique_id"],
                        pkt.get("campaign_technique_name"),
                    )
                proto = pkt["protocol"]
                nbytes = pkt["bytes_transferred"]
                if pkt.get("scripted_description"):
                    log["anomaly_description"] = pkt["scripted_description"]
                elif detail["mv_flag"] and not detail["z_flag"]:
                    # Caught by the multivariate model, invisible to the z-score:
                    # exactly the scan/DoS/brute-force class the old detector missed.
                    # IMPORTANT: keep this text PURELY behavioural — never embed a
                    # detector/model name here. This string is used as the RAG
                    # retrieval query, and words like "Isolation(Forest)" pull the
                    # query toward the wrong techniques (Virtualization/Sandbox
                    # Evasion, Hide Artifacts). Include protocol + byte count so the
                    # semantic-translation layer can reason about data volume.
                    log["anomaly_description"] = (
                        f"Anomalous {proto} network flow carrying {nbytes} bytes whose "
                        f"behavioural profile deviates sharply from the learned normal "
                        f"baseline for this host."
                    )
                elif detail["mv_flag"] and detail["z_flag"]:
                    log["anomaly_description"] = (
                        f"Anomalous {proto} network flow carrying {nbytes} bytes: its byte "
                        f"volume is {z_score} standard deviations above the rolling baseline "
                        f"and its behavioural profile also deviates from normal."
                    )
                else:
                    log["anomaly_description"] = (
                        f"Anomalous {proto} network flow carrying {nbytes} bytes: byte volume "
                        f"is {z_score} standard deviations above the rolling baseline."
                    )

            await websocket.send_json(log)
            await asyncio.sleep(settings.stream_interval)

    except WebSocketDisconnect:
        print("Frontend dashboard closed the connection. Halting stream.")
    except (RuntimeError, ConnectionResetError):
        print("Socket already closed. Halting stream.")
    except asyncio.CancelledError:
        print("Stream task cancelled (server shutdown).")
        raise


# ---------------------------------------------------------------------------
# SOAR: block / unblock (API key + human-in-the-loop confirmation)
# ---------------------------------------------------------------------------


@app.post("/api/block-ip")
async def block_ip(payload: BlockIPRequest, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)

    if soar.confirmation_required() and not payload.analyst_confirmed:
        raise HTTPException(
            status_code=428,
            detail="Analyst confirmation required. Re-submit with "
            "analyst_confirmed=true to authorise this containment action.",
        )

    try:
        soar.validate_ip(payload.target_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    try:
        return await asyncio.to_thread(soar.block_ip, payload.target_ip)
    except Exception as e:
        db.log_incident(payload.target_ip, "BLOCK", "error", str(e))
        raise HTTPException(status_code=500, detail=f"Failed to apply firewall rules: {e}")


@app.post("/api/unblock-ip")
async def unblock_ip(payload: BlockIPRequest, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    try:
        soar.validate_ip(payload.target_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    return await asyncio.to_thread(soar.unblock_ip, payload.target_ip)


# ---------------------------------------------------------------------------
# Incident log
# ---------------------------------------------------------------------------


@app.get("/api/incidents")
async def get_incidents(limit: int = 25):
    return {"incidents": db.get_incidents(limit)}
