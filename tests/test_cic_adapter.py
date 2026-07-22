"""CIC-IDS-2017 adapter tests (run against a bundled synthetic sample CSV).

Validate the gold-standard adapter's contract without the gated multi-GB
download — including the two CIC-IDS-2017 quirks: leading-space headers and
Infinity/NaN values in the flow-rate columns.
"""

import os

import numpy as np

from omnishield import datasets_cic as c
from omnishield.config import settings
from omnishield.detection import IsolationForestDetector

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "evaluation", "data", "cic_sample.csv")


def _with_sample(fn):
    old = settings.cic_csv
    settings.cic_csv = SAMPLE
    try:
        return fn()
    finally:
        settings.cic_csv = old


def test_feature_matrix_clean_and_byte_signal():
    X, y, b = _with_sample(c.load_feature_matrix)
    assert X.shape[1] == len(c.CANONICAL_NUMERIC_COLS) == 78
    assert set(y.tolist()) == {0, 1}
    # The Infinity/NaN in Flow Bytes/s must have been coerced away.
    assert np.isfinite(X).all()
    assert np.allclose(b, X[:, c.SRC_BYTES_FEATURE_IDX] + X[:, c.DST_BYTES_FEATURE_IDX])


def test_leading_space_headers_are_handled():
    # If header stripping failed, every feature would read as 0 and no attack
    # would ever be flagged. This asserts the columns were actually parsed.
    X, y, _ = _with_sample(c.load_feature_matrix)
    assert X[y == 1].sum() > 0


def test_labeled_records_shape():
    recs = _with_sample(c.load_labeled_records)
    assert recs
    required = {"protocol", "src_ip", "dst_ip", "bytes", "features", "label",
                "is_attack", "attack_type", "attack_category"}
    for r in recs:
        assert required <= set(r)
        assert len(r["features"]) == 78
    assert any(r["is_attack"] for r in recs)
    assert all(r["label"] == "normal" for r in recs if not r["is_attack"])


def test_attack_category_mapping():
    assert c.attack_category("PortScan") == "probe"
    assert c.attack_category("DDoS") == "dos"
    assert c.attack_category("DoS Hulk") == "dos"
    assert c.attack_category("Bot") == "botnet"
    assert c.attack_category("Heartbleed") == "heartbleed"
    assert c.attack_category("Web Attack \u2013 XSS") == "webattack"
    assert c.attack_category("FTP-Patator") == "bruteforce"
    for cat in set(v for v in [c.attack_category(l) for l in
                   ("PortScan", "DDoS", "Bot", "Infiltration", "Heartbleed",
                    "Web Attack \u2013 XSS", "FTP-Patator")]):
        assert cat in c.CATEGORY_PHRASE


def test_isolationforest_separates_sample_attacks():
    X, y, _ = _with_sample(c.load_feature_matrix)
    det = IsolationForestDetector(contamination=0.1).fit(X[y == 0])
    flagged = det.predict(X[y == 1])
    assert flagged.sum() / len(flagged) > 0.6
