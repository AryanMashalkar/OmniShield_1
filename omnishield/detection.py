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

baseline_window: deque = deque(maxlen=settings.baseline_window_size)


def evaluate_packet(bytes_transferred: int) -> tuple[bool, float]:
    """Rolling z-score evaluation of a single packet (production path)."""
    if len(baseline_window) < settings.min_baseline_samples:
        baseline_window.append(bytes_transferred)
        return False, 0.0

    mean = statistics.mean(baseline_window)
    stdev = statistics.stdev(baseline_window)

    z = 0.0 if stdev == 0 else (bytes_transferred - mean) / stdev
    is_anomaly = z >= settings.anomaly_z_threshold

    if not is_anomaly:  # anti-poisoning: don't fold anomalies into the baseline
        baseline_window.append(bytes_transferred)

    return is_anomaly, round(z, 2)


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


STREAMING_DETECTORS = [RollingZScoreDetector, EWMADetector]
BATCH_DETECTORS = [
    IsolationForestDetector,
    OneClassSVMDetector,
    PCAReconstructionDetector,
]
