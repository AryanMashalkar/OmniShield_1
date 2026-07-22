"""Data-integrity tests for the datasets and the MITRE RAG corpus (no LLM).

These guard against silent drift, e.g. a labeled example whose gold technique is
missing from the embedded knowledge base (which would make RAG unable to ever
retrieve it).
"""

import json
import os

from omnishield.datasets import load_labeled_records
from omnishield.mitre import load_mitre_documents

DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "evaluation", "data", "attribution_labeled.json"
)


def _load_examples():
    with open(DATA_PATH, encoding="utf-8") as f:
        return json.load(f)["examples"]


def test_replay_records_carry_consistent_feature_vectors():
    recs = load_labeled_records(limit=500)
    assert recs
    assert all(isinstance(r.get("features"), list) for r in recs)
    dims = {len(r["features"]) for r in recs}
    assert len(dims) == 1, f"inconsistent feature dimensionality: {dims}"


def test_attribution_dataset_is_wellformed():
    examples = _load_examples()
    assert len(examples) >= 40
    for ex in examples:
        assert ex["anomaly_description"].strip()
        assert ex["source_ip"].strip()
        assert ex["gold_ids"], "each example needs at least one gold technique"
        for gid in ex["gold_ids"]:
            assert gid.startswith("T") and gid[1:].isdigit(), f"bad gold id {gid}"


def test_mitre_corpus_covers_every_gold_technique():
    docs = load_mitre_documents()
    assert len(docs) > 150
    corpus_ids = {d.metadata["id"] for d in docs}
    gold = set()
    for ex in _load_examples():
        gold.update(ex["gold_ids"])
    missing = sorted(g for g in gold if g not in corpus_ids)
    assert missing == [], f"gold techniques absent from RAG corpus: {missing}"


def test_mitre_documents_are_enriched_with_tactics():
    # At least most techniques should carry a tactic string — the retrieval
    # signal that lifted hit@k from 0.33 to ~0.83.
    docs = load_mitre_documents()
    with_tactics = [d for d in docs if d.metadata.get("tactics")]
    assert len(with_tactics) / len(docs) > 0.8
