"""Per-entity UEBA baselines + incident/campaign correlation tests (offline)."""

from omnishield import correlation
from omnishield.detection import (
    entity_profiles,
    evaluate_packet,
    reset_baselines,
)


# ---------------------------------------------------------------------------
# Per-entity UEBA baselines
# ---------------------------------------------------------------------------


def test_baseline_is_scored_per_entity():
    reset_baselines()
    # Warm two distinct hosts with their own (different) normal profiles.
    for i in range(15):
        evaluate_packet(1000 + i * 20, None, entity="hostA")
        evaluate_packet(50 + i, None, entity="hostB")

    # A 1 MB flow is wildly anomalous for hostA's baseline, scored against hostA.
    is_anom, z, detail = evaluate_packet(1_000_000, None, entity="hostA")
    assert is_anom is True
    assert detail["baseline_scope"] == "entity"
    assert detail["entity"] == "hostA"


def test_cold_start_entity_uses_population_baseline():
    reset_baselines()
    # Warm the shared population baseline via many hosts.
    for i in range(20):
        evaluate_packet(1000 + i * 10, None, entity=f"host{i}")
    # A brand-new host with no history of its own falls back to population scope.
    _, _, detail = evaluate_packet(1200, None, entity="brand_new_host")
    assert detail["baseline_scope"] in ("population", "learning")


def test_entity_profiles_lists_learned_hosts():
    reset_baselines()
    for i in range(12):
        evaluate_packet(500 + i, None, entity="profiled_host")
    profiles = entity_profiles()
    entities = {p["entity"] for p in profiles}
    assert "profiled_host" in entities
    p = next(p for p in profiles if p["entity"] == "profiled_host")
    assert p["samples"] >= 10 and p["warm"] is True


# ---------------------------------------------------------------------------
# Incident / campaign correlation
# ---------------------------------------------------------------------------


def test_campaign_orders_techniques_along_killchain():
    correlation.reset()
    entity = "10.0.0.5"
    # Record out of kill-chain order — the engine must re-order them.
    correlation.record_attribution(entity, "T1041", "Exfiltration Over C2 Channel")  # exfil
    correlation.record_attribution(entity, "T1046", "Network Service Discovery")     # discovery
    correlation.record_attribution(entity, "T1021", "Remote Services")               # lateral movement

    camps = correlation.get_campaigns()
    camp = next(c for c in camps if c["entity"] == entity)
    assert camp["stages"] == ["discovery", "lateral movement", "exfiltration"]
    assert camp["stage_span"] == 3
    # Forecast comes off the furthest stage (exfiltration -> impact).
    assert camp["forecast"]["current_tactic"] == "exfiltration"


def test_campaign_groups_weak_signals_without_attribution():
    correlation.reset()
    for _ in range(5):
        correlation.record_anomaly("10.0.0.9", category="dos")
    camp = correlation.get_campaigns()[0]
    assert camp["entity"] == "10.0.0.9"
    assert camp["anomaly_count"] == 5
    assert camp["stages"] == []


def test_multistage_campaigns_rank_first():
    correlation.reset()
    correlation.record_anomaly("10.0.0.1")  # single weak signal
    correlation.record_attribution("10.0.0.2", "T1046", "Network Service Discovery")
    correlation.record_attribution("10.0.0.2", "T1021", "Remote Services")
    camps = correlation.get_campaigns()
    assert camps[0]["entity"] == "10.0.0.2"  # richer story ranks first


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def test_entities_endpoint(client):
    r = client.get("/api/entities")
    assert r.status_code == 200
    assert "entities" in r.json()


def test_campaigns_endpoint(client):
    correlation.reset()
    correlation.record_attribution("203.0.113.7", "T1110", "Brute Force")
    r = client.get("/api/campaigns")
    assert r.status_code == 200
    camps = r.json()["campaigns"]
    assert any(c["entity"] == "203.0.113.7" for c in camps)
