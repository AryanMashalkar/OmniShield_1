"""Unit tests for the hybrid live detector (no server, no LLM)."""

from omnishield.detection import (
    baseline_window,
    evaluate_packet,
    get_live_multivariate_detector,
)


def test_multivariate_detector_warms_up():
    assert get_live_multivariate_detector() is not None


def test_evaluate_packet_returns_triple_with_detail():
    is_anom, z, detail = evaluate_packet(1234, None)
    assert isinstance(is_anom, bool)
    assert isinstance(z, float)
    assert {"detector", "z_flag", "z_score", "mv_flag", "mv_score"} <= set(detail)


def test_zscore_fallback_flags_byte_spike_when_no_features():
    # Byte-only telemetry (features=None) must fall back to the z-score and
    # still catch an extreme exfil spike.
    baseline_window.clear()
    for i in range(20):
        evaluate_packet(1000 + i * 25, None)  # varied normals -> non-zero stdev
    is_anom, z, detail = evaluate_packet(4_200_000_000, None)
    assert is_anom is True
    assert detail["detector"] == "RollingZScore"
    assert z >= 3.0


def test_isolationforest_flags_labeled_attacks():
    # The multivariate detector should flag the large majority of real NSL-KDD
    # attacks it is shown (the whole point of the live upgrade).
    from omnishield.datasets import load_labeled_records

    det = get_live_multivariate_detector()
    attacks = [
        r for r in load_labeled_records(limit=4000)
        if r["is_attack"] and r.get("features")
    ][:200]
    assert attacks, "expected labeled attack records with feature vectors"
    flagged = [det.predict_one(r["features"])[0] for r in attacks]
    assert sum(flagged) / len(flagged) > 0.6
