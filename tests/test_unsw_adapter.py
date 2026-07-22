"""UNSW-NB15 adapter tests (run against a bundled synthetic sample CSV).

These validate the modern-dataset adapter's contract without needing the gated
multi-GB download: schema parsing, the byte-signal feature positions, record
shape, attack-category mapping, and that a one-class IsolationForest fitted on
the sample's normal traffic separates its attacks.
"""

import os

import numpy as np

from omnishield import datasets_unsw as u
from omnishield.config import settings
from omnishield.detection import IsolationForestDetector

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "evaluation", "data", "unsw_sample.csv")


def _with_sample(fn):
    old = settings.unsw_csv
    settings.unsw_csv = SAMPLE
    try:
        return fn()
    finally:
        settings.unsw_csv = old


def test_feature_matrix_shape_and_byte_signal():
    X, y, b = _with_sample(u.load_feature_matrix)
    assert X.shape[1] == len(u.CANONICAL_NUMERIC_COLS) == 39
    assert set(y.tolist()) == {0, 1}
    # The univariate byte signal must equal sbytes+dbytes at the known positions.
    assert np.allclose(b, X[:, u.SRC_BYTES_FEATURE_IDX] + X[:, u.DST_BYTES_FEATURE_IDX])


def test_labeled_records_shape():
    recs = _with_sample(u.load_labeled_records)
    assert recs
    required = {"protocol", "src_ip", "dst_ip", "bytes", "features", "label",
                "is_attack", "attack_type", "attack_category"}
    for r in recs:
        assert required <= set(r)
        assert len(r["features"]) == 39
    normals = [r for r in recs if not r["is_attack"]]
    attacks = [r for r in recs if r["is_attack"]]
    assert normals and attacks
    assert all(r["label"] == "normal" for r in normals)


def test_attack_category_mapping():
    assert u.attack_category("DoS") == "dos"
    assert u.attack_category("Reconnaissance") == "probe"
    assert u.attack_category("Exploits") == "exploit"
    assert u.attack_category("Worms") == "worm"
    # Every mapped category must have a behavioural phrase for RAG steering.
    for cat in set(u.UNSW_CATEGORY.values()):
        assert cat in u.CATEGORY_PHRASE


def test_isolationforest_separates_sample_attacks():
    X, y, _ = _with_sample(u.load_feature_matrix)
    det = IsolationForestDetector(contamination=0.1).fit(X[y == 0])
    flagged = det.predict(X[y == 1])
    assert flagged.sum() / len(flagged) > 0.6


def test_dispatcher_defaults_to_nsl_kdd():
    # The public facade must stay on NSL-KDD unless OMNISHIELD_DATASET is set,
    # so the offline default and the rest of the suite never break.
    from omnishield import datasets

    assert datasets.DATASET_NAME == "NSL-KDD"
