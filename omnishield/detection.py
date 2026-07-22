"""Anomaly-detection algorithms.

Two families share a common evaluation interface (``fit`` / ``score_samples`` /
``predict``):

Streaming (univariate byte-transfer signal):
    * ``RollingZScoreDetector`` — OmniShield's own production detector.
    * ``EWMADetector``          — exponentially-weighted moving average baseline.

Batch (multivariate NSL-KDD feature matrix):
    * ``IsolationForestDetector``
    * ``OneClassSVMDetector``
    * ``PCAReconstructionDetector`` — PCA reconstruction error (autoencoder-style).

The streaming detectors are also used live by the WebSocket stream through the
module-level ``evaluate_packet`` helper, preserving the original behaviour
(rolling window, anti-baseline-poisoning: flagged packets are not folded back
into the baseline stats).
"""

from __future__ import annotations

import statistics
from collections import deque

from .config import settings

# ---------------------------------------------------------------------------
# Live streaming detector (module-level singleton used by the WebSocket)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Per-entity UEBA baselines (User & Entity Behaviour Analytics)
# ---------------------------------------------------------------------------
#
# Instead of one global threshold, OmniShield learns a *behavioural profile per
# entity* (source host / device / segment) — exactly what PS#7 asks for. Each
# entity gets its own rolling byte-transfer baseline; a flow is scored against
# ITS OWN host's normal, not a population average. A shared population window is
# kept as a cold-start fallback so brand-new / rarely-seen entities are still
# scored immediately. This cuts false positives (a chatty file server isn't
# flagged for being chatty; a normally-silent host spiking is) and is the honest
# answer to "how is this different from a static threshold?".

_GLOBAL = "__population__"
_entity_windows: dict[str, deque] = {}


def _window(entity: str) -> deque:
    win = _entity_windows.get(entity)
    if win is None:
        win = deque(maxlen=settings.baseline_window_size)
        _entity_windows[entity] = win
    return win


# Back-compat alias: the shared population/fallback baseline window.
baseline_window: deque = _window(_GLOBAL)

# Lazily-fitted multivariate detector used by the live pipeline (see
# ``get_live_multivariate_detector``). ``_mv_state`` guards against re-fitting.
_live_multivariate = None
_mv_state = "cold"  # "cold" -> "ready" | "unavailable"


def reset_baselines() -> None:
    """Clear every learned baseline (used by tests)."""
    _entity_windows.clear()
    global baseline_window
    baseline_window = _window(_GLOBAL)


def _rolling_zscore(bytes_transferred: float, entity: str | None = None) -> tuple[bool, float, str]:
    """Per-entity streaming z-score on the byte-transfer signal.

    Scores against the entity's own baseline once it has enough history, else
    against the shared population baseline (cold start). Returns
    ``(is_anomaly, z, scope)`` where scope is "entity" | "population" | "learning".
    """
    pop = _window(_GLOBAL)
    is_entity = bool(entity) and entity != _GLOBAL
    ent = _window(entity) if is_entity else pop

    if is_entity and len(ent) >= settings.min_baseline_samples:
        scoring, scope = ent, "entity"
    elif len(pop) >= settings.min_baseline_samples:
        scoring, scope = pop, "population"
    else:
        # Cold start: seed baselines, don't score yet.
        ent.append(bytes_transferred)
        if ent is not pop:
            pop.append(bytes_transferred)
        return False, 0.0, "learning"

    mean = statistics.mean(scoring)
    stdev = statistics.stdev(scoring)
    z = 0.0 if stdev == 0 else (bytes_transferred - mean) / stdev
    is_anomaly = z >= settings.anomaly_z_threshold

    if not is_anomaly:  # anti-poisoning: never fold anomalies into a baseline
        ent.append(bytes_transferred)
        if ent is not pop:
            pop.append(bytes_transferred)

    return is_anomaly, round(z, 2), scope


def entity_profiles(limit: int = 25) -> list[dict]:
    """Learned per-entity behavioural baselines, most-active first."""
    profiles = []
    for entity, win in _entity_windows.items():
        if entity == _GLOBAL or not win:
            continue
        mean = statistics.mean(win) if win else 0.0
        stdev = statistics.stdev(win) if len(win) > 1 else 0.0
        profiles.append(
            {
                "entity": entity,
                "samples": len(win),
                "mean_bytes": round(mean, 1),
                "stdev_bytes": round(stdev, 1),
                "warm": len(win) >= settings.min_baseline_samples,
            }
        )
    profiles.sort(key=lambda p: p["samples"], reverse=True)
    return profiles[:limit]


def get_live_multivariate_detector():
    """Return a one-class IsolationForest fitted on NSL-KDD normal traffic.

    Fitted once, lazily. This is the population-level model: a multivariate
    detector (F1 ~= 0.93 on NSL-KDD) that catches the scan/DoS/brute-force attacks
    the univariate z-score (F1 ~= 0.15) structurally cannot see. Returns ``None``
    if disabled or if fitting fails, in which case the pipeline falls back to the
    per-entity z-score alone.
    """
    global _live_multivariate, _mv_state
    if _mv_state != "cold":
        return _live_multivariate

    _mv_state = "unavailable"  # pessimistic until we succeed
    if not settings.multivariate_enabled:
        print("[OmniShield] Multivariate live detector disabled by config.")
        return None
    try:
        import numpy as np

        from .datasets import DATASET_NAME, load_feature_matrix

        X, y, _ = load_feature_matrix(limit=settings.multivariate_train_limit)
        X_normal = X[y == 0]
        if len(X_normal) < 50:
            print("[OmniShield] Too few normal samples to fit multivariate detector.")
            return None
        det = IsolationForestDetector(contamination=settings.multivariate_contamination)
        det.fit(X_normal)
        _live_multivariate = det
        _mv_state = "ready"
        print(
            f"[OmniShield] Live multivariate detector ready "
            f"(IsolationForest fitted on {len(X_normal)} normal {DATASET_NAME} flows)."
        )
    except Exception as e:  # pragma: no cover - defensive: never break the stream
        print(f"[OmniShield] Multivariate detector unavailable ({e}); z-score only.")
        _live_multivariate = None
    return _live_multivariate


def evaluate_packet(
    bytes_transferred: float, features=None, entity: str | None = None
) -> tuple[bool, float, dict]:
    """Hybrid, entity-aware evaluation of a single live packet.

    Decision rule (precision-first, the SOC default):
      * If a multivariate feature vector is available AND the IsolationForest is
        fitted, **IsolationForest is authoritative** (F1 ~= 0.93 on NSL-KDD). The
        per-entity rolling z-score still runs in parallel and is reported as a
        corroborating fast-path byte-spike indicator.
      * If no feature vector is available (degraded / byte-only telemetry), the
        pipeline degrades gracefully to the per-entity z-score alone.

    ``entity`` (source host/device) selects the behavioural baseline; see the
    per-entity UEBA section above.

    Returns ``(is_anomaly, z_score, detail)``.
    """
    z_flag, z, scope = _rolling_zscore(bytes_transferred, entity)

    mv_flag = False
    mv_score = None
    mv_ready = False

    if features is not None:
        det = get_live_multivariate_detector()
        if det is not None:
            mv_flag, mv_score = det.predict_one(features)
            mv_ready = True

    if mv_ready:
        detector = "IsolationForest"  # authoritative on full telemetry
        is_anomaly = mv_flag
    else:
        detector = "RollingZScore"  # per-entity fallback on byte-only telemetry
        is_anomaly = z_flag

    detail = {
        "detector": detector,
        "z_flag": z_flag,
        "z_score": z,
        "mv_flag": mv_flag,
        "mv_score": mv_score,
        "mv_ready": mv_ready,
        "entity": entity or _GLOBAL,
        "baseline_scope": scope,  # "entity" | "population" | "learning"
    }
    return is_anomaly, z, detail


# ---------------------------------------------------------------------------
# Evaluation-time detectors (used by evaluation/eval_detection.py)
# ---------------------------------------------------------------------------


class BaseDetector:
    name = "base"

    def fit(self, X_normal):  # noqa: D401 - simple interface
        return self

    def predict(self, X):
        raise NotImplementedError


class RollingZScoreDetector(BaseDetector):
    """OmniShield's streaming rolling z-score, evaluated sequentially.

    Operates on a univariate signal (byte totals). Mirrors ``evaluate_packet``
    including the anti-poisoning rule.
    """

    name = "RollingZScore"

    def __init__(self, window=None, threshold=None, min_samples=None):
        self.window = window or settings.baseline_window_size
        self.threshold = threshold or settings.anomaly_z_threshold
        self.min_samples = min_samples or settings.min_baseline_samples

    def fit(self, X_normal):
        return self  # streaming detector needs no batch fit

    def predict(self, signal):
        import numpy as np

        signal = np.asarray(signal, dtype=float).ravel()
        win: deque = deque(maxlen=self.window)
        preds = np.zeros(len(signal), dtype=int)
        for i, v in enumerate(signal):
            if len(win) < self.min_samples:
                win.append(v)
                continue
            mean = statistics.mean(win)
            stdev = statistics.stdev(win)
            z = 0.0 if stdev == 0 else (v - mean) / stdev
            if z >= self.threshold:
                preds[i] = 1
            else:
                win.append(v)
        return preds


class EWMADetector(BaseDetector):
    """Exponentially-weighted moving average control-chart baseline."""

    name = "EWMA"

    def __init__(self, alpha=0.1, k=3.0, min_samples=None):
        self.alpha = alpha
        self.k = k
        self.min_samples = min_samples or settings.min_baseline_samples

    def fit(self, X_normal):
        return self

    def predict(self, signal):
        import numpy as np

        signal = np.asarray(signal, dtype=float).ravel()
        preds = np.zeros(len(signal), dtype=int)
        ewma = None
        ewvar = 0.0
        seen = 0
        for i, v in enumerate(signal):
            if ewma is None:
                ewma = v
                seen = 1
                continue
            diff = v - ewma
            sd = ewvar ** 0.5
            if seen >= self.min_samples and sd > 0 and diff > self.k * sd:
                preds[i] = 1
                continue  # anti-poisoning: don't update stats on anomalies
            ewma = self.alpha * v + (1 - self.alpha) * ewma
            ewvar = (1 - self.alpha) * (ewvar + self.alpha * diff * diff)
            seen += 1
        return preds


class IsolationForestDetector(BaseDetector):
    name = "IsolationForest"

    def __init__(self, contamination=0.1, random_state=42):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=contamination, random_state=random_state, n_estimators=100
        )

    def fit(self, X_normal):
        Xs = self.scaler.fit_transform(X_normal)
        self.model.fit(Xs)
        return self

    def predict(self, X):
        Xs = self.scaler.transform(X)
        # sklearn: -1 = outlier, 1 = inlier -> map to 1 = anomaly
        return (self.model.predict(Xs) == -1).astype(int)

    def predict_one(self, vec) -> tuple[bool, float | None]:
        """Score a single live feature vector -> (is_anomaly, anomaly_score).

        ``anomaly_score`` is ``-decision_function`` so higher = more anomalous.
        Returns ``(False, None)`` on any shape/type mismatch rather than raising,
        so a malformed live packet can never take the stream down.
        """
        try:
            import numpy as np

            x = np.asarray(vec, dtype=float).reshape(1, -1)
            if x.shape[1] != getattr(self.scaler, "n_features_in_", x.shape[1]):
                return False, None
            xs = self.scaler.transform(x)
            is_anomaly = bool(self.model.predict(xs)[0] == -1)
            score = float(self.model.decision_function(xs)[0])
            return is_anomaly, round(-score, 4)
        except Exception:
            return False, None


class OneClassSVMDetector(BaseDetector):
    name = "OneClassSVM"

    def __init__(self, nu=0.1, gamma="scale", max_train=5000):
        from sklearn.svm import OneClassSVM
        from sklearn.preprocessing import StandardScaler

        self.scaler = StandardScaler()
        self.model = OneClassSVM(nu=nu, gamma=gamma, kernel="rbf")
        self.max_train = max_train  # OCSVM is O(n^2); cap training size

    def fit(self, X_normal):
        import numpy as np

        if len(X_normal) > self.max_train:
            idx = np.random.RandomState(42).choice(
                len(X_normal), self.max_train, replace=False
            )
            X_normal = X_normal[idx]
        Xs = self.scaler.fit_transform(X_normal)
        self.model.fit(Xs)
        return self

    def predict(self, X):
        Xs = self.scaler.transform(X)
        return (self.model.predict(Xs) == -1).astype(int)


class PCAReconstructionDetector(BaseDetector):
    """PCA reconstruction-error detector (linear autoencoder analogue).

    Fits PCA on normal traffic, flags samples whose reconstruction error
    exceeds a high percentile of the normal-traffic error distribution.
    """

    name = "PCAReconstruction"

    def __init__(self, n_components=0.95, percentile=99):
        from sklearn.decomposition import PCA
        from sklearn.preprocessing import StandardScaler

        self.scaler = StandardScaler()
        self.pca = PCA(n_components=n_components)
        self.percentile = percentile
        self.threshold_ = None

    def _recon_error(self, Xs):
        import numpy as np

        proj = self.pca.transform(Xs)
        recon = self.pca.inverse_transform(proj)
        return np.mean((Xs - recon) ** 2, axis=1)

    def fit(self, X_normal):
        import numpy as np

        Xs = self.scaler.fit_transform(X_normal)
        self.pca.fit(Xs)
        errs = self._recon_error(Xs)
        self.threshold_ = np.percentile(errs, self.percentile)
        return self

    def predict(self, X):
        Xs = self.scaler.transform(X)
        return (self._recon_error(Xs) > self.threshold_).astype(int)


class HybridZScoreIForestDetector(BaseDetector):
    """Recall-first *union* of IsolationForest and the streaming z-score.

    Flags a sample if **either** detector fires. Benchmarked to document the
    design decision behind the live pipeline: the union reaches the highest
    recall of any detector (~0.97) but its precision cost (IsolationForest's
    ~0.95 -> ~0.72) means analyst alert fatigue. The live pipeline
    (``evaluate_packet``) therefore uses IsolationForest as the *authoritative*
    detector with the z-score as a fast-path indicator/fallback, rather than
    this union.
    """

    name = "Union_IForest_ZScore"

    def __init__(self, contamination=0.1):
        self.iforest = IsolationForestDetector(contamination=contamination)
        self.zscore = RollingZScoreDetector()

    def fit(self, X_normal):
        self.iforest.fit(X_normal)
        return self

    def predict(self, X):
        import numpy as np

        from .datasets import DST_BYTES_FEATURE_IDX, SRC_BYTES_FEATURE_IDX

        X = np.asarray(X, dtype=float)
        byte_signal = X[:, SRC_BYTES_FEATURE_IDX] + X[:, DST_BYTES_FEATURE_IDX]
        z_preds = self.zscore.predict(byte_signal)
        mv_preds = self.iforest.predict(X)
        return ((z_preds == 1) | (mv_preds == 1)).astype(int)


STREAMING_DETECTORS = [RollingZScoreDetector, EWMADetector]
BATCH_DETECTORS = [
    IsolationForestDetector,
    OneClassSVMDetector,
    PCAReconstructionDetector,
    HybridZScoreIForestDetector,
]
