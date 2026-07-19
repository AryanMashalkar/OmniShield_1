"""Attack-attribution evaluation: RAG vs zero-shot ablation.

Runs OmniShield's attribution pipeline over a labeled anomaly->MITRE dataset in
two modes and reports:

  * top-1 accuracy   — did the LLM's chosen technique ID match a gold ID?
  * retrieval hit@k  — (RAG only) was a gold ID among the retrieved techniques?
  * mean latency and valid-JSON rate.

This directly answers the research question "does retrieval grounding improve
LLM attack attribution?" and requires a running Ollama (llama3.1:8b + nomic).

Usage:
    python -m evaluation.eval_attribution
    python -m evaluation.eval_attribution --limit 8      # quick smoke run
"""

import argparse
import json
import os
import time

from evaluation._common import print_table, save_results
from omnishield import llm

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "attribution_labeled.json")


def load_dataset(limit=None):
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    examples = data["examples"]
    return examples[:limit] if limit else examples


def run_mode(examples, mode):
    correct = 0
    retrieval_hits = 0
    valid_json = 0
    latencies = []
    per_item = []

    for ex in examples:
        gold = set(ex["gold_ids"])
        t0 = time.perf_counter()
        if mode == "rag":
            result = llm.attribute_attack_rag(ex["anomaly_description"], ex["source_ip"])
        else:
            result = llm.attribute_attack_zeroshot(ex["anomaly_description"], ex["source_ip"])
        latencies.append(time.perf_counter() - t0)

        got = str(result.get("matched_technique_id", "")).strip().upper()
        is_correct = got in gold
        correct += int(is_correct)
        if "parse_error" not in result:
            valid_json += 1

        retrieved = set(result.get("_retrieved_ids", []) or [])
        hit = bool(gold & retrieved)
        retrieval_hits += int(hit)

        per_item.append(
            {
                "gold_ids": sorted(gold),
                "predicted": got,
                "correct": is_correct,
                "retrieval_hit": hit if mode == "rag" else None,
            }
        )

    n = len(examples)
    summary = {
        "mode": mode,
        "n": n,
        "top1_accuracy": round(correct / n, 4),
        "valid_json_rate": round(valid_json / n, 4),
        "mean_latency_sec": round(sum(latencies) / n, 3),
    }
    if mode == "rag":
        summary["retrieval_hit_at_k"] = round(retrieval_hits / n, 4)
    return summary, per_item


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="limit examples (0 = all)")
    ap.add_argument("--modes", default="rag,zeroshot", help="comma list: rag,zeroshot")
    args = ap.parse_args()
    limit = args.limit or None

    examples = load_dataset(limit)
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    print(f"[eval_attribution] {len(examples)} examples | modes={modes}\n")
    if "rag" in modes:
        print("[eval_attribution] Warming up vector store / LLM (first call is slow)...")

    summaries = []
    details = {}
    for mode in modes:
        print(f"  running mode={mode} ...")
        summary, per_item = run_mode(examples, mode)
        summaries.append(summary)
        details[mode] = per_item

    print("\n=== Attribution Benchmark (RAG vs zero-shot) ===\n")
    cols = ["mode", "n", "top1_accuracy", "retrieval_hit_at_k", "valid_json_rate", "mean_latency_sec"]
    print_table(summaries, cols)

    payload = {"dataset": "attribution_labeled", "summaries": summaries, "details": details}
    path = save_results("attribution", payload)
    print(f"\n[eval_attribution] Results saved to {path}")


if __name__ == "__main__":
    main()
