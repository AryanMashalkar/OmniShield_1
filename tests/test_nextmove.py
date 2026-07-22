"""Next-Move Predictor tests (ATT&CK kill-chain forecast) + its API endpoint.

No LLM required — the forecast is a deterministic graph walk, so these run offline.
"""

from omnishield.nextmove import TACTIC_ORDER, predict_next_moves


def test_discovery_predicts_lateral_movement():
    r = predict_next_moves("T1046")  # Network Service Discovery
    assert r["known"] and not r["terminal"]
    assert r["current_tactic"] == "discovery"
    tactics = [p["tactic"] for p in r["predictions"]]
    assert "lateral movement" in tactics


def test_initial_access_predicts_execution():
    r = predict_next_moves("T1190")  # Exploit Public-Facing Application (Heartbleed)
    assert r["current_tactic"] == "initial access"
    assert r["predictions"][0]["tactic"] == "execution"
    # Each predicted stage carries flagship techniques + a defensive priority.
    assert r["predictions"][0]["techniques"]
    assert r["predictions"][0]["defence"]


def test_impact_is_terminal():
    r = predict_next_moves("T1498")  # Network Denial of Service
    assert r["terminal"] is True
    assert r["predictions"] == []


def test_unknown_technique_is_flagged_not_guessed():
    r = predict_next_moves("T9999")
    assert r["known"] is False
    assert r["predictions"] == []


def test_horizon_limits_forecast_depth():
    r = predict_next_moves("T1190", horizon=3)
    assert len(r["predictions"]) == 3
    r1 = predict_next_moves("T1190", horizon=1)
    assert len(r1["predictions"]) == 1


def test_tactic_order_is_the_full_killchain():
    assert TACTIC_ORDER[0] == "reconnaissance"
    assert TACTIC_ORDER[-1] == "impact"
    assert len(TACTIC_ORDER) == 14


def test_next_moves_endpoint(client):
    r = client.get("/api/next-moves?technique_id=T1046")
    assert r.status_code == 200
    body = r.json()
    assert body["current_tactic"] == "discovery"
    assert any(p["tactic"] == "lateral movement" for p in body["predictions"])
