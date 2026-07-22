"""End-to-end API smoke tests (via Starlette TestClient — no live server needed).

LLM-dependent checks are skipped automatically when Ollama is unavailable, so the
non-LLM contract (health, live detection stream, SOAR governance gate, audit log)
always runs — even in CI / offline.
"""

from ollama_probe import requires_ollama


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_health(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "online"
    assert body["stream_mode"] == "replay"


# ---------------------------------------------------------------------------
# Live detection stream (IsolationForest + z-score hybrid — no LLM)
# ---------------------------------------------------------------------------


def test_websocket_stream_detects_and_attributes(client):
    seen = {"n": 0, "anom": 0}
    detectors = set()
    with client.websocket_connect("/ws/network-stream") as ws:
        for _ in range(40):
            msg = ws.receive_json()
            seen["n"] += 1
            # Every frame must carry the detector-attribution fields.
            assert "detector" in msg
            assert "mv_flag" in msg
            if msg.get("is_anomaly"):
                seen["anom"] += 1
                detectors.add(msg["detector"])
    assert seen["n"] == 40
    # Replay mode streams real labeled attacks, so we must see anomalies,
    # and the multivariate engine must be the one attributing them.
    assert seen["anom"] > 0
    assert "IsolationForest" in detectors


# ---------------------------------------------------------------------------
# SOAR governance gate (safe: these paths never reach the firewall)
# ---------------------------------------------------------------------------


def test_soar_requires_human_confirmation(client, api_key):
    # Valid key but no analyst_confirmed -> HTTP 428 before any action.
    r = client.post(
        "/api/block-ip",
        headers={"X-API-Key": api_key},
        json={"target_ip": "185.199.108.153"},
    )
    assert r.status_code == 428


def test_soar_rejects_bad_api_key(client):
    r = client.post(
        "/api/block-ip",
        headers={"X-API-Key": "WRONG"},
        json={"target_ip": "185.199.108.153", "analyst_confirmed": True},
    )
    assert r.status_code == 401


def test_soar_rejects_invalid_ip(client, api_key):
    # Confirmed + valid key but malformed IP -> 400 (still no firewall call).
    r = client.post(
        "/api/block-ip",
        headers={"X-API-Key": api_key},
        json={"target_ip": "not-an-ip", "analyst_confirmed": True},
    )
    assert r.status_code == 400


def test_incident_log_endpoint(client):
    r = client.get("/api/incidents?limit=5")
    assert r.status_code == 200
    assert "incidents" in r.json()


# ---------------------------------------------------------------------------
# LLM-backed endpoints (skipped if Ollama is unavailable)
# ---------------------------------------------------------------------------


@requires_ollama
def test_scam_analyzer_flags_digital_arrest(client):
    transcript = (
        "This is the CBI. A warrant has been issued in your name. Stay on this "
        "video call, do not disconnect, and transfer the funds to this account "
        "to clear your name or you will be arrested."
    )
    r = client.post("/api/analyze-scam", json={"transcript": transcript})
    assert r.status_code == 200
    body = r.json()
    assert body.get("is_threat") is True
    assert isinstance(body.get("threat_score"), (int, float))


@requires_ollama
def test_attribution_rag_returns_valid_technique(client):
    r = client.post(
        "/api/attribute-attack",
        json={
            "anomaly_description": "Thousands of rapid failed login attempts against the VPN gateway from one external host in a minute.",
            "source_ip": "203.0.113.9",
            "mode": "rag",
        },
    )
    assert r.status_code == 200
    tid = str(r.json().get("matched_technique_id", ""))
    assert tid.startswith("T") and tid[1:].isdigit()


@requires_ollama
def test_attribution_zeroshot_returns_valid_technique(client):
    r = client.post(
        "/api/attribute-attack",
        json={
            "anomaly_description": "Sequential connection attempts to 5000 TCP ports on a single host, characteristic of a port scan.",
            "source_ip": "198.51.100.4",
            "mode": "zeroshot",
        },
    )
    assert r.status_code == 200
    tid = str(r.json().get("matched_technique_id", ""))
    assert tid.startswith("T") and tid[1:].isdigit()
