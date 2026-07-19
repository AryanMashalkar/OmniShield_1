import asyncio
import random
import subprocess
import ipaddress
import sqlite3
import os
import csv
import io
import statistics
import urllib.request
from collections import deque
from datetime import datetime
import json

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document

app = FastAPI(title="OmniShield AI Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# API Key Auth (protects state-changing SOAR actions)
# ---------------------------------------------------------------------------

DEFAULT_DEV_KEY = "omnishield-dev-key-2026"
API_KEY = os.environ.get("OMNISHIELD_API_KEY", DEFAULT_DEV_KEY)

if API_KEY == DEFAULT_DEV_KEY:
    print(
        "[WARNING] OMNISHIELD_API_KEY not set — using an insecure default dev key. "
        "Fine for a hackathon demo on localhost, do NOT ship this as-is."
    )


def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

# ---------------------------------------------------------------------------
# SQLite Incident Log
# ---------------------------------------------------------------------------

DB_PATH = "omnishield.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def log_incident(target_ip: str, action: str, status: str, details: str = ""):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO incidents (timestamp, target_ip, action, status, details) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), target_ip, action, status, details),
    )
    conn.commit()
    conn.close()


init_db()

# ---------------------------------------------------------------------------
# Real MITRE ATT&CK Enterprise Knowledge Base
# ---------------------------------------------------------------------------

MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_CACHE_FILE = "mitre_attack_cache.json"
MAX_TECHNIQUES = 250  # top-level Enterprise techniques currently number ~222

FALLBACK_MITRE_DOCS = [
    Document(
        page_content="Technique ID: T1566 - Phishing. Adversaries send phishing messages to gain access to victim systems via social engineering, spearphishing attachments, or malicious links.",
        metadata={"id": "T1566", "name": "Phishing"}
    ),
    Document(
        page_content="Technique ID: T1041 - Exfiltration Over C2 Channel. Adversaries steal data by transferring it through an established command and control channel, causing unexpected outbound bandwidth spikes.",
        metadata={"id": "T1041", "name": "Exfiltration Over C2"}
    ),
    Document(
        page_content="Technique ID: T1059 - Command and Scripting Interpreter. Adversaries execute commands or scripts through PowerShell or Cmd to bypass administrative controls.",
        metadata={"id": "T1059", "name": "Scripting Interpreter Execution"}
    ),
    Document(
        page_content="Technique ID: T1078 - Valid Accounts. Adversaries compromise existing credentials to gain unauthorized access to internal systems and database endpoints.",
        metadata={"id": "T1078", "name": "Valid Accounts"}
    )
]


def fetch_mitre_stix_bundle() -> dict:
    if os.path.exists(MITRE_CACHE_FILE):
        with open(MITRE_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    print("[OmniShield] Downloading MITRE ATT&CK Enterprise dataset (first run only)...")
    with urllib.request.urlopen(MITRE_ATTACK_URL, timeout=60) as response:
        data = json.loads(response.read().decode("utf-8"))

    with open(MITRE_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)

    return data


def load_mitre_documents() -> list[Document]:
    try:
        bundle = fetch_mitre_stix_bundle()
    except Exception as e:
        print(f"[WARNING] Could not fetch MITRE ATT&CK dataset ({e}). Falling back to built-in sample techniques.")
        return FALLBACK_MITRE_DOCS

    docs = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        attack_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break

        if not attack_id or "." in attack_id:
            continue

        name = obj.get("name", "Unknown Technique")
        description = (obj.get("description") or "").split("\n")[0]

        docs.append(
            Document(
                page_content=f"Technique ID: {attack_id} - {name}. {description}",
                metadata={"id": attack_id, "name": name}
            )
        )

        if len(docs) >= MAX_TECHNIQUES:
            break

    if not docs:
        print("[WARNING] Parsed 0 techniques from MITRE dataset. Falling back to built-in sample techniques.")
        return FALLBACK_MITRE_DOCS

    print(f"[OmniShield] Loaded {len(docs)} real MITRE ATT&CK Enterprise techniques into the knowledge base.")
    return docs

# ---------------------------------------------------------------------------
# Real Network Traffic Samples (NSL-KDD dataset)
# ---------------------------------------------------------------------------
# Sources realistic byte-transfer sizes and protocols for the simulated
# "normal" background traffic in the Packet Inspection Stream, instead of
# pure random.randint(). NSL-KDD is a well-known, published network
# intrusion detection benchmark dataset (a refined version of KDDCup'99),
# ~126k labeled connection records. We only use records labeled "normal"
# here — the scripted attack event (4.2GB exfil to a known-bad IP) stays
# as-is, since that's the deliberate demo trigger, not something we want
# randomized.

NSL_KDD_URL = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
NSL_KDD_CACHE_FILE = "nsl_kdd_cache.csv"
MAX_PACKET_BYTES_DISPLAY = 200_000  # clamp so rare multi-MB records don't visually overwhelm the live feed


def fetch_nsl_kdd_raw() -> str:
    if os.path.exists(NSL_KDD_CACHE_FILE):
        with open(NSL_KDD_CACHE_FILE, "r", encoding="utf-8") as f:
            return f.read()

    print("[OmniShield] Downloading NSL-KDD network traffic dataset (first run only)...")
    with urllib.request.urlopen(NSL_KDD_URL, timeout=60) as response:
        raw = response.read().decode("utf-8", errors="ignore")

    with open(NSL_KDD_CACHE_FILE, "w", encoding="utf-8") as f:
        f.write(raw)

    return raw


def load_normal_traffic_samples() -> list[tuple[str, int]]:
    """Parses real 'normal'-labeled connection records from NSL-KDD into
    (protocol, byte_count) tuples. Falls back to an empty list if the
    dataset can't be fetched — sample_packet() then uses synthetic values."""
    try:
        raw = fetch_nsl_kdd_raw()
    except Exception as e:
        print(f"[WARNING] Could not fetch NSL-KDD dataset ({e}). Falling back to synthetic packet sizes.")
        return []

    samples = []
    reader = csv.reader(io.StringIO(raw))
    for row in reader:
        if len(row) < 42:
            continue
        protocol_type = row[1]
        src_bytes = row[4]
        dst_bytes = row[5]
        label = row[41]

        if label != "normal":
            continue

        try:
            total_bytes = int(src_bytes) + int(dst_bytes)
        except ValueError:
            continue

        if total_bytes <= 0:
            continue

        samples.append((protocol_type.upper(), total_bytes))

    if not samples:
        print("[WARNING] Parsed 0 usable NSL-KDD samples. Falling back to synthetic packet sizes.")
        return []

    print(f"[OmniShield] Loaded {len(samples)} real network traffic samples (NSL-KDD dataset) for packet simulation.")
    return samples


NSL_KDD_SAMPLES = load_normal_traffic_samples()


def sample_packet() -> tuple[str, int]:
    """Returns (protocol, bytes_transferred) for one simulated background
    packet. Sampled from real NSL-KDD traffic records when available,
    otherwise falls back to the original synthetic random values."""
    if NSL_KDD_SAMPLES:
        protocol, total_bytes = random.choice(NSL_KDD_SAMPLES)
        return protocol, min(total_bytes, MAX_PACKET_BYTES_DISPLAY)
    return random.choice(["TCP", "UDP", "ICMP"]), random.randint(100, 5000)

# ---------------------------------------------------------------------------
# Real-Time Statistical Anomaly Detection (rolling z-score thresholding)
# ---------------------------------------------------------------------------
# Replaces the old `counter % 10` scripted trigger. We keep a rolling window
# of recent "baseline" byte-transfer sizes and flag any packet whose z-score
# (distance from the rolling mean, in standard deviations) clears
# ANOMALY_Z_THRESHOLD. The scripted 4.2GB exfil scenario is still injected
# periodically for demo reliability, but it is no longer force-flagged — it
# has to clear the same statistical check as everything else. Flagged
# packets are NOT folded back into the baseline, so a genuine spike can't
# poison the rolling stats for subsequent packets.

BASELINE_WINDOW_SIZE = 40      # how many recent "normal" samples we keep as the rolling baseline
ANOMALY_Z_THRESHOLD = 3.0      # flag anything >= 3 standard deviations from baseline mean
MIN_BASELINE_SAMPLES = 10      # need this many samples before z-scoring is meaningful

baseline_window = deque(maxlen=BASELINE_WINDOW_SIZE)


def evaluate_packet(bytes_transferred: int) -> tuple[bool, float]:
    """
    Returns (is_anomaly, z_score) for a given byte count using a rolling
    mean/stdev of recent baseline traffic (real z-score thresholding, not a
    hardcoded flag).
    """
    if len(baseline_window) < MIN_BASELINE_SAMPLES:
        baseline_window.append(bytes_transferred)
        return False, 0.0

    mean = statistics.mean(baseline_window)
    stdev = statistics.stdev(baseline_window)

    z_score = 0.0 if stdev == 0 else (bytes_transferred - mean) / stdev
    is_anomaly = z_score >= ANOMALY_Z_THRESHOLD

    if not is_anomaly:
        baseline_window.append(bytes_transferred)

    return is_anomaly, round(z_score, 2)

# ---------------------------------------------------------------------------
# Model & Vector Store Initialization
# ---------------------------------------------------------------------------

llm = OllamaLLM(model="llama3.1:8b")
embeddings = OllamaEmbeddings(model="nomic-embed-text")

persist_directory = "./chroma_db_mitre"

if os.path.isdir(persist_directory) and os.listdir(persist_directory):
    print("[OmniShield] Loading cached MITRE ATT&CK vector store from disk...")
    vectorstore = Chroma(persist_directory=persist_directory, embedding_function=embeddings)
else:
    mitre_docs = load_mitre_documents()
    print(f"[OmniShield] Embedding {len(mitre_docs)} techniques (first run only — this can take a minute or two)...")
    vectorstore = Chroma.from_documents(
        documents=mitre_docs,
        embedding=embeddings,
        persist_directory=persist_directory
    )

retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

# ---------------------------------------------------------------------------
# Robust LLM JSON helper (retry once, then structured fallback)
# ---------------------------------------------------------------------------


def parse_llm_json(raw_text: str) -> dict:
    if not raw_text:
        raise ValueError("Empty LLM response")

    cleaned = raw_text.strip().replace("```json", "").replace("```", "").strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(cleaned[start:end + 1])

    raise ValueError("No JSON object found in LLM response")


def invoke_llm_json(prompt: str, fallback: dict, retries: int = 1) -> dict:
    last_raw = None
    for _ in range(retries + 1):
        last_raw = llm.invoke(prompt)
        try:
            return parse_llm_json(last_raw)
        except Exception:
            continue

    result = dict(fallback)
    result["parse_error"] = "LLM did not return valid JSON after retry"
    result["raw_analysis"] = last_raw
    return result

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class ScamAnalysisRequest(BaseModel):
    transcript: str

class AnomalyAttributionRequest(BaseModel):
    anomaly_description: str
    source_ip: str
    anomaly_score: float | None = None  # z-score from the rolling detector, if available

class BlockIPRequest(BaseModel):
    target_ip: str

# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

@app.get("/")
def health_check():
    return {"status": "online", "system": "OmniShield AI Core"}

# ---------------------------------------------------------------------------
# Scam Transcript Analysis
# ---------------------------------------------------------------------------

@app.post("/api/analyze-scam")
async def analyze_scam(payload: ScamAnalysisRequest):
    prompt = f"""
    You are a Cybersecurity Incident Response AI.
    Analyze this transcript for social engineering or digital arrest scams:
    "{payload.transcript}"

    Respond strictly in valid JSON format with these exact keys:
    {{
        "is_threat": true/false,
        "threat_score": 0-100,
        "coercion_tactics": ["tactic1", "tactic2"],
        "summary": "1-sentence summary"
    }}
    Do not include markdown blocks or extra text.
    """
    fallback = {
        "is_threat": False,
        "threat_score": 0,
        "coercion_tactics": [],
        "summary": "Analysis failed - LLM did not return valid JSON after retry."
    }
    return invoke_llm_json(prompt, fallback)

# ---------------------------------------------------------------------------
# RAG-based Attack Attribution
# ---------------------------------------------------------------------------

@app.post("/api/attribute-attack")
async def attribute_attack(payload: AnomalyAttributionRequest):
    docs = retriever.invoke(payload.anomaly_description)
    context = "\n".join([doc.page_content for doc in docs])

    score_line = (
        f'Statistical Detector Output: z-score = {payload.anomaly_score} '
        f'(flagged, threshold = {ANOMALY_Z_THRESHOLD})'
        if payload.anomaly_score is not None
        else "Statistical Detector Output: not available"
    )

    prompt = f"""
    You are a SOC Threat Intelligence Analyst.
    Map this network anomaly to the most relevant MITRE ATT&CK technique using the retrieved knowledge.

    Anomaly Event: "{payload.anomaly_description}" from IP: {payload.source_ip}
    {score_line}
    Retrieved MITRE Reference Data:
    {context}

    Respond strictly in valid JSON format:
    {{
        "matched_technique_id": "TXXXX",
        "technique_name": "Name",
        "confidence_score": 0-100,
        "recommended_action": "Short containment step"
    }}
    Do not include markdown formatting or commentary outside the JSON.
    """
    fallback = {
        "matched_technique_id": "UNKNOWN",
        "technique_name": "Unclassified",
        "confidence_score": 0,
        "recommended_action": "Manual review required - AI classification failed."
    }
    return invoke_llm_json(prompt, fallback)

# ---------------------------------------------------------------------------
# Live Network Stream (WebSocket)
# ---------------------------------------------------------------------------

@app.websocket("/ws/network-stream")
async def network_stream(websocket: WebSocket):
    """
    Simulates a live feed of network logs. Background "normal" traffic
    sources its protocol + byte-size from real NSL-KDD connection records
    (see sample_packet()) instead of pure randomness. IPs and timestamps
    stay synthetic — this is a plausible-traffic simulation, not a replay
    of a captured session.

    Anomaly detection is now handled by evaluate_packet(): a rolling
    mean/stdev z-score computed over recent baseline traffic. The scripted
    4.2GB exfil scenario is still injected periodically (for demo
    reliability — we can't wait around for a real attack), but it is a
    *candidate* packet that must clear the same z-score threshold as
    everything else, not a hardcoded is_anomaly=True. Against a baseline of
    KB-scale NSL-KDD traffic it will always clear the threshold by a huge
    margin, but the flag itself is produced by the detector.
    """
    await websocket.accept()
    try:
        counter = 0
        while True:
            counter += 1

            # Periodically inject the scripted exfil scenario as a candidate
            # packet. Gated on baseline being warmed up so it can't poison
            # evaluate_packet()'s rolling stats before real thresholds exist.
            inject_scripted_event = (
                counter % 12 == 0 and len(baseline_window) >= MIN_BASELINE_SAMPLES
            )

            if inject_scripted_event:
                source_ip = "192.168.1.45"
                destination_ip = "185.199.108.153"
                protocol = "TCP"
                bytes_transferred = 4_200_000_000
                scripted_description = (
                    "Workstation suddenly transferred 4.2GB of encrypted files to "
                    "an external IP at 2:00 AM after executing a PowerShell script."
                )
            else:
                protocol, bytes_transferred = sample_packet()
                source_ip = f"192.168.1.{random.randint(10, 50)}"
                destination_ip = f"10.0.0.{random.randint(1, 10)}"
                scripted_description = None

            is_anomaly, z_score = evaluate_packet(bytes_transferred)

            log = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol,
                "bytes_transferred": bytes_transferred,
                "status": "Critical" if is_anomaly else "Normal",
                "is_anomaly": is_anomaly,
                "anomaly_score": z_score,
            }

            if is_anomaly:
                log["anomaly_description"] = scripted_description or (
                    f"Statistical anomaly: byte-transfer size is {z_score} standard "
                    f"deviations above the rolling baseline (threshold {ANOMALY_Z_THRESHOLD})."
                )

            await websocket.send_json(log)
            await asyncio.sleep(2)

    except WebSocketDisconnect:
        print("Frontend dashboard closed the connection. Halting stream.")

    except (RuntimeError, ConnectionResetError):
        print("Socket already closed. Halting stream.")

    except asyncio.CancelledError:
        print("Stream task cancelled (server shutdown).")
        raise

# ---------------------------------------------------------------------------
# Block IP (Windows Firewall Isolation) — requires X-API-Key header
# ---------------------------------------------------------------------------

@app.post("/api/block-ip")
async def block_ip(payload: BlockIPRequest, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)

    try:
        ipaddress.ip_address(payload.target_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    target_ip = payload.target_ip
    rule_base = f"OmniShield_Block_{target_ip}"

    try:
        subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                f"Get-NetFirewallRule -DisplayName '{rule_base}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
            ],
            capture_output=True, text=True
        )

        rule_specs = [
            ("Outbound", "TCP"),
            ("Inbound",  "TCP"),
            ("Outbound", "UDP"),
            ("Inbound",  "UDP"),
            ("Outbound", "ICMPv4"),
            ("Inbound",  "ICMPv4"),
        ]

        errors = []
        for direction, protocol in rule_specs:
            display_name = f"{rule_base}_{protocol}_{direction}"
            ps_cmd = (
                f"New-NetFirewallRule -DisplayName '{display_name}' "
                f"-Direction {direction} -RemoteAddress {target_ip} "
                f"-Protocol {protocol} -Action Block -Profile Any -Enabled True"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                errors.append(f"{display_name}: {result.stderr.strip()}")

        if errors:
            log_incident(target_ip, "BLOCK", "partial_failure", "; ".join(errors))
            return {
                "status": "partial_failure",
                "message": f"Some rules failed to apply for {target_ip}. Ensure Uvicorn is running as Administrator.",
                "errors": errors
            }

        log_incident(target_ip, "BLOCK", "success", "TCP/UDP/ICMP blocked, both directions")
        return {
            "status": "success",
            "message": f"Full isolation applied for {target_ip} (TCP/UDP/ICMP blocked, both directions)"
        }

    except Exception as e:
        log_incident(target_ip, "BLOCK", "error", str(e))
        raise HTTPException(status_code=500, detail=f"Failed to apply firewall rules: {e}")

# ---------------------------------------------------------------------------
# Unblock IP — requires X-API-Key header
# ---------------------------------------------------------------------------

@app.post("/api/unblock-ip")
async def unblock_ip(payload: BlockIPRequest, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)

    try:
        ipaddress.ip_address(payload.target_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    rule_base = f"OmniShield_Block_{payload.target_ip}"
    result = subprocess.run(
        [
            "powershell", "-NoProfile", "-Command",
            f"Get-NetFirewallRule -DisplayName '{rule_base}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
        ],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        log_incident(payload.target_ip, "UNBLOCK", "error", result.stderr.strip())
        return {"status": "error", "message": result.stderr.strip()}

    log_incident(payload.target_ip, "UNBLOCK", "success", "All rules removed")
    return {"status": "success", "message": f"All rules removed for {payload.target_ip}"}

# ---------------------------------------------------------------------------
# Incident Log
# ---------------------------------------------------------------------------

@app.get("/api/incidents")
async def get_incidents(limit: int = 25):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, timestamp, target_ip, action, status, details FROM incidents ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return {"incidents": [dict(row) for row in rows]}
