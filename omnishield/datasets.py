"""Pluggable network-traffic dataset dispatcher.

Selects the active dataset adapter via ``OMNISHIELD_DATASET``:

    "nsl_kdd"   (default) — refined KDDCup'99, auto-cached, works offline.
    "unsw_nb15"           — modern (2015) set; drop the CSV in and point
                            OMNISHIELD_UNSW_CSV at it.
    "cic_ids"             — CIC-IDS-2017 (gold standard); point
                            OMNISHIELD_CIC_CSV at a MachineLearningCVE flow CSV.

Every adapter exposes the same interface, so the detection pipeline, the live
WebSocket stream and the evaluation harness are completely dataset-agnostic:

    DATASET_NAME
    SRC_BYTES_FEATURE_IDX / DST_BYTES_FEATURE_IDX   (byte-signal positions)
    CATEGORY_PHRASE                                  (attack-category -> English)
    attack_category(label)
    load_feature_matrix(limit)          -> (X, y, byte_signal)
    load_labeled_records(limit, shuffle)-> list[record dict]
    load_normal_feature_samples()       -> list[{protocol, bytes, features}]
    sample_feature_packet(samples)      -> (protocol, bytes, features)

Adding a new dataset (CIC-IDS-2017, ToN_IoT, live Zeek/NetFlow, ...) is a matter
of writing one more adapter module with this same surface.
"""

from .config import settings


def _select_adapter():
    """Pick the adapter for OMNISHIELD_DATASET.

    Modern datasets (UNSW-NB15, CIC-IDS-2017) are gated user-supplied CSVs. If
    the selected one's file is missing we fall back to NSL-KDD (which self-caches)
    with a loud warning — so a mis-set env var degrades to a working demo instead
    of crashing the live stream / eval.
    """
    name = settings.dataset
    if name in ("unsw_nb15", "unsw", "unsw-nb15"):
        from . import datasets_unsw as adapter
    elif name in ("cic_ids", "cic", "cic_ids2017", "cic-ids-2017", "cicids2017"):
        from . import datasets_cic as adapter
    else:
        from . import datasets_nsl as adapter
        return adapter

    if not adapter.is_available():
        from . import datasets_nsl as nsl

        print(
            f"\n[OmniShield][WARNING] OMNISHIELD_DATASET='{name}' was selected but its "
            f"dataset file was not found.\n"
            f"    Falling back to NSL-KDD so the stream/eval keep working. Set the CSV "
            f"path (OMNISHIELD_UNSW_CSV / OMNISHIELD_CIC_CSV) to use the modern set.\n"
        )
        return nsl
    return adapter


_adapter = _select_adapter()

# --- Re-exported per-dataset constants (resolved once, at import) -----------
DATASET_NAME = _adapter.DATASET_NAME
SRC_BYTES_FEATURE_IDX = _adapter.SRC_BYTES_FEATURE_IDX
DST_BYTES_FEATURE_IDX = _adapter.DST_BYTES_FEATURE_IDX
CATEGORY_PHRASE = _adapter.CATEGORY_PHRASE
MITRE_HINTS = getattr(_adapter, "MITRE_HINTS", {})


# --- Delegated adapter interface -------------------------------------------
def attack_category(label):
    return _adapter.attack_category(label)


def load_feature_matrix(limit=None):
    return _adapter.load_feature_matrix(limit=limit)


def load_labeled_records(limit=None, shuffle=False):
    return _adapter.load_labeled_records(limit=limit, shuffle=shuffle)


def load_normal_feature_samples():
    return _adapter.load_normal_feature_samples()


def sample_feature_packet(samples):
    return _adapter.sample_feature_packet(samples)
