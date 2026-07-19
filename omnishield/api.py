"""FastAPI application: REST + WebSocket surface for the OmniShield SOC."""

import asyncio
import random
from datetime import datetime

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import db, llm, soar
from .config import settings
from .datasets import load_labeled_records, load_normal_traffic_samples, sample_packet
from .detection import evaluate_packet, baseline_window
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

# Background traffic samples for the simulated stream (loaded once).
NSL_KDD_SAMPLES = load_normal_traffic_samples()
# Labeled records for the replay stream (lazy — only if replay mode is used).
_REPLAY_RECORDS: list[dict] | None = None


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
        return await asyncio.to_thread(
            llm.attribute_attack_zeroshot, payload.anomaly_description, payload.source_ip
        )
    return await asyncio.to_thread(
        llm.attribute_attack_rag,
        payload.anomaly_description,
        payload.source_ip,
        payload.anomaly_score,
    )


# ---------------------------------------------------------------------------
# Live network stream
# ---------------------------------------------------------------------------


def _simulated_packet(counter: int) -> dict:
    inject_scripted = counter % 12 == 0 and len(baseline_window) >= settings.min_baseline_samples
    if inject_scripted:
        return {
            "source_ip": "192.168.1.45",
            "destination_ip": "185.199.108.153",
            "protocol": "TCP",
            "bytes_transferred": 4_200_000_000,
            "scripted_description": (
                "Workstation suddenly transferred 4.2GB of encrypted files to an "
                "external IP at 2:00 AM after executing a PowerShell script."
            ),
        }
    protocol, bytes_transferred = sample_packet(NSL_KDD_SAMPLES)
    return {
        "source_ip": f"192.168.1.{random.randint(10, 50)}",
        "destination_ip": f"10.0.0.{random.randint(1, 10)}",
        "protocol": protocol,
        "bytes_transferred": bytes_transferred,
        "scripted_description": None,
    }


def _replay_packet(counter: int) -> dict:
    global _REPLAY_RECORDS
    if _REPLAY_RECORDS is None:
        _REPLAY_RECORDS = load_labeled_records(shuffle=True)
    rec = _REPLAY_RECORDS[counter % len(_REPLAY_RECORDS)]
    desc = None
    if rec["is_attack"]:
        desc = (
            f"Replayed NSL-KDD record labeled '{rec['attack_type']}' "
            f"({rec['protocol']}, {rec['bytes']} bytes) to an external host."
        )
    return {
        "source_ip": rec["src_ip"],
        "destination_ip": rec["dst_ip"],
        "protocol": rec["protocol"],
        "bytes_transferred": rec["bytes"],
        "scripted_description": desc,
        "ground_truth_label": rec["label"],
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

            is_anomaly, z_score = evaluate_packet(pkt["bytes_transferred"])

            log = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "source_ip": pkt["source_ip"],
                "destination_ip": pkt["destination_ip"],
                "protocol": pkt["protocol"],
                "bytes_transferred": pkt["bytes_transferred"],
                "status": "Critical" if is_anomaly else "Normal",
                "is_anomaly": is_anomaly,
                "anomaly_score": z_score,
            }
            if "ground_truth_label" in pkt:
                log["ground_truth_label"] = pkt["ground_truth_label"]
            if is_anomaly:
                log["anomaly_description"] = pkt.get("scripted_description") or (
                    f"Statistical anomaly: byte-transfer size is {z_score} standard "
                    f"deviations above the rolling baseline "
                    f"(threshold {settings.anomaly_z_threshold})."
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
