"""Dataset dispatcher tests: selection + graceful fallback.

Guards the fix for a mis-set OMNISHIELD_DATASET (a modern dataset selected
without its CSV present) taking down the live stream / eval with an unhandled
FileNotFoundError.
"""

import os

from omnishield import datasets
from omnishield.config import settings

CIC_SAMPLE = os.path.join(os.path.dirname(__file__), "..", "evaluation", "data", "cic_sample.csv")
UNSW_SAMPLE = os.path.join(os.path.dirname(__file__), "..", "evaluation", "data", "unsw_sample.csv")


def _select(dataset, **overrides):
    saved = {k: getattr(settings, k) for k in ("dataset", "cic_csv", "unsw_csv")}
    settings.dataset = dataset
    for k, v in overrides.items():
        setattr(settings, k, v)
    try:
        return datasets._select_adapter()
    finally:
        for k, v in saved.items():
            setattr(settings, k, v)


def test_missing_cic_falls_back_to_nsl():
    adapter = _select("cic_ids", cic_csv="definitely_missing_cic_12345.csv")
    assert adapter.DATASET_NAME == "NSL-KDD"


def test_missing_unsw_falls_back_to_nsl():
    adapter = _select("unsw_nb15", unsw_csv="definitely_missing_unsw_12345.csv")
    assert adapter.DATASET_NAME == "NSL-KDD"


def test_cic_selected_when_file_present():
    adapter = _select("cic_ids", cic_csv=CIC_SAMPLE)
    assert adapter.DATASET_NAME == "CIC-IDS-2017"


def test_unsw_selected_when_file_present():
    adapter = _select("unsw_nb15", unsw_csv=UNSW_SAMPLE)
    assert adapter.DATASET_NAME == "UNSW-NB15"


def test_default_is_nsl():
    assert _select("nsl_kdd").DATASET_NAME == "NSL-KDD"
    # Unknown values also default to NSL-KDD.
    assert _select("something_else").DATASET_NAME == "NSL-KDD"
