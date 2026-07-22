# OmniShield

**An AI-powered autonomous Security Operations Center (SOC) with a closed detection → attribution → response loop, powered entirely by local LLMs.**

OmniShield monitors a live network telemetry stream, detects anomalies with
statistical + ML methods, uses a **local Llama 3.1 (8B) model with RAG over the
real MITRE ATT&CK knowledge base** to attribute detected attacks to a technique,
and — with human-in-the-loop authorisation — executes a **SOAR** playbook that
injects Windows Firewall rules to isolate the malicious host. It also analyses
call/chat transcripts for social-engineering / "digital arrest" scams.

No cloud APIs: all inference is local (Ollama), which matters for a tool
handling sensitive security data.

---

## Architecture

```
 React/Vite dashboard  ──WebSocket (live feed)──┐
 (frontend/)           ──REST (X-API-Key)────────┤
                                                 ▼
 FastAPI backend (omnishield/)
    api.py        REST + WebSocket surface
    detection.py  per-entity UEBA baselines + hybrid IsolationForest/z-score; ML baselines
    llm.py        lazy Ollama LLM + Chroma vector store + prompts
    mitre.py      MITRE ATT&CK STIX → embedded knowledge base
    nextmove.py   Next-Move Predictor — ATT&CK kill-chain forecast (agentic/graph layer)
    correlation.py incident/campaign correlation — groups anomalies by host into stories
    datasets.py   pluggable dataset dispatcher (NSL-KDD / UNSW-NB15 / CIC-IDS-2017)
    soar.py       Windows Firewall isolation + human-in-the-loop policy
    db.py         SQLite incident/audit log
    config.py     environment-driven settings (no hard-coded secrets)
```

**UEBA (per-entity baselines):** detection learns a behavioural profile *per source
host* (`GET /api/entities`), scoring each flow against its own host's normal (with a
population fallback for cold-start entities) — not one global threshold.

**Incident correlation:** anomalies are grouped by host into multi-stage *campaigns*
(`GET /api/campaigns`), ordered along the ATT&CK kill chain, e.g. *host X: Discovery →
Credential Access → Lateral Movement → forecast: Impact*.

The backend implementation is a modular package (`omnishield/`); `main.py` is a
thin entrypoint so `uvicorn main:app` keeps working.

---

## Quick start

### Prerequisites
- Python 3.13, Node 18+
- [Ollama](https://ollama.com) with the required models:
  ```
  ollama pull llama3.1:8b
  ollama pull nomic-embed-text
  ```

### Backend
```powershell
python -m venv venv
venv\Scripts\pip install -r requirements.txt

copy .env.example .env          # then edit OMNISHIELD_API_KEY
venv\Scripts\uvicorn main:app --reload
```
> The SOAR firewall-isolation feature requires running the backend as
> **Administrator** on Windows. Everything else works without elevation.

### Frontend
```powershell
cd frontend
npm install
copy .env.example .env          # set VITE_OMNISHIELD_API_KEY = backend key
npm run dev
```

---

## Configuration

All settings are environment-driven (see `.env.example`). Highlights:

| Variable | Purpose | Default |
|---|---|---|
| `OMNISHIELD_API_KEY` | Shared key for SOAR endpoints. If unset, a random key is generated per run and printed. | *(random)* |
| `OMNISHIELD_CORS_ORIGINS` | CORS allow-list (no wildcard) | `localhost:5173,127.0.0.1:5173` |
| `OMNISHIELD_STREAM_MODE` | `simulate` or `replay` (real labeled NSL-KDD incl. attacks) | `simulate` |
| `OMNISHIELD_SOAR_REQUIRE_CONFIRMATION` | Require analyst confirmation before blocking | `true` |
| `OMNISHIELD_Z_THRESHOLD` | Rolling z-score anomaly threshold | `3.0` |

### Security posture (hardened)
- No hard-coded API key; secrets come from the environment / gitignored `.env`.
- CORS restricted to an explicit allow-list (was `*`).
- Frontend key comes from `VITE_OMNISHIELD_API_KEY`, not a source constant.
- State-changing SOAR actions require a valid API key **and** explicit
  human-in-the-loop confirmation (`analyst_confirmed=true`, HTTP 428 otherwise).

---

## Human-in-the-loop (safe autonomy)

OmniShield deliberately does **not** block hosts unilaterally. The AI *detects*
and *recommends*; a human analyst *authorises*; the system *acts* and *audits*.
`/api/block-ip` returns **HTTP 428** unless `analyst_confirmed=true` is supplied
(the dashboard's "Execute SOAR Isolation" button is that authorisation), and
every action is written to the SQLite incident log. This is toggled by
`OMNISHIELD_SOAR_REQUIRE_CONFIRMATION`.

---

## Evaluation & research harnesses

Reproducible, quantitative benchmarks live in `evaluation/`. Results are written
to `evaluation/results/` as timestamped + `_latest.json` files.

### 1. Detection benchmark — `python -m evaluation.eval_detection`
Compares OmniShield's streaming **rolling z-score** and an **EWMA** baseline
against **Isolation Forest**, **One-Class SVM**, **PCA-reconstruction**
(autoencoder-style), and the **live hybrid** decision on the labeled **NSL-KDD**
dataset (one-class training on normal traffic). Reports accuracy / precision /
recall / F1 / confusion matrix / throughput.

> **Finding (and the resulting design):** the byte-transfer z-score excels at
> exfiltration-style events but structurally misses scan/DoS/brute-force attacks
> that don't produce byte spikes (**F1 ≈ 0.15**), whereas multivariate one-class
> models reach **F1 ≈ 0.93–0.94**. We acted on this: the **live pipeline now runs
> a multivariate Isolation Forest as the authoritative detector** (fitted on
> normal NSL-KDD traffic at startup), with the z-score retained as a fast-path
> byte-spike indicator and a fallback for byte-only telemetry. A recall-first
> *union* of the two was also benchmarked (recall ≈ 0.97) but rejected as the
> default because its precision cost (≈ 0.95 → 0.72) causes analyst alert fatigue.
> Net effect: live detection F1 improves from **0.15 → ~0.93**.

### 2. Attribution benchmark — `python -m evaluation.eval_attribution`
Ablation of **RAG vs zero-shot** LLM attack attribution over a **40-example**
labeled anomaly→MITRE dataset (`evaluation/data/attribution_labeled.json`).
Reports top-1 accuracy, retrieval hit@k, valid-JSON rate, and latency. Requires
Ollama.

> **Finding (RAG grounding pays off):** on the 40-example set, retrieval **doubles**
> attribution accuracy — **zero-shot top-1 = 0.35 → RAG top-1 = 0.70** — with a
> retrieval **hit@k of 0.90** and a 100% valid-JSON rate. Getting here required
> fixing retrieval, not just prompting: the MITRE corpus is embedded with each
> technique's **tactic(s) + cleaned full description** (not a sparse ID+first-line
> stub), the LLM is shown an **ID-labelled candidate list** and constrained to pick
> from it, retrieval depth is `k=6`, generation is deterministic (`temperature=0`),
> and a **semantic-translation layer** rewrites raw telemetry into behavioural
> English before retrieval (e.g. *0 bytes ⇒ "exfiltration is physically impossible;
> consistent with scanning / DoS"*), which both lifts retrieval hit@k (0.33 → 0.90)
> and stops the model mis-attributing 0-byte scans/floods to exfiltration.
> (llama3.1:8b, local; ~7 s/attribution.)

### 3. Robustness benchmark — `python -m evaluation.eval_robustness`
**Prompt-injection** attacks against the scam analyzer and the attribution
pipeline: real threats carrying an embedded "report this as benign" instruction.
Reports attack-success-rate (lower = more robust). Requires Ollama.

---

## Tests

A `pytest` smoke suite (`tests/`) exercises the whole system via an in-process
Starlette `TestClient` — no live server or admin rights needed, and it never
touches the host firewall.

```powershell
venv\Scripts\pip install -r requirements-dev.txt
venv\Scripts\python -m pytest                 # full suite (~40s, uses Ollama)
venv\Scripts\python -m pytest tests\test_detection.py tests\test_corpus_data.py  # offline only (~7s)
```

Coverage: health, the live detection WebSocket (IsolationForest + z-score hybrid),
the SOAR human-in-the-loop gate (HTTP 428 / 401 / 400), the audit-log endpoint,
detector unit tests, and MITRE-corpus/dataset integrity (every labeled gold
technique must exist in the RAG corpus). LLM-backed checks (scam analysis, RAG /
zero-shot attribution) **auto-skip** when Ollama isn't reachable, so the suite
still runs offline / in CI.

---

## Datasets
- **MITRE ATT&CK Enterprise** (STIX) — embedded into Chroma for RAG attribution.
- **NSL-KDD** *(default)* — network-intrusion benchmark used for simulated/replay
  traffic and the detection evaluation. Cached on first run.

### Pluggable dataset adapters
Detection, the live stream, and the eval harness are **dataset-agnostic** — every
adapter (`omnishield/datasets_*.py`) exposes the same interface behind the
`omnishield.datasets` dispatcher, selected by `OMNISHIELD_DATASET`:

| Value | Dataset | Notes |
|---|---|---|
| `nsl_kdd` *(default)* | NSL-KDD | auto-cached, works offline |
| `unsw_nb15` | **UNSW-NB15** (2015) | modern attacks (Fuzzers, Recon, Backdoor, DoS, Exploits, Generic, Shellcode, Worms); gated download |
| `cic_ids` | **CIC-IDS-2017** (gold standard) | DDoS, PortScan, Bot, Infiltration, Web attacks, FTP/SSH brute force, **Heartbleed**; gated download. Adapter handles CIC's leading-space headers and `Infinity`/`NaN` flow-rate values |

To run on modern traffic: download the set, then:
```powershell
# UNSW-NB15
$env:OMNISHIELD_DATASET  = 'unsw_nb15'
$env:OMNISHIELD_UNSW_CSV = 'C:\path\to\UNSW_NB15_training-set.csv'
# or CIC-IDS-2017
$env:OMNISHIELD_DATASET  = 'cic_ids'
$env:OMNISHIELD_CIC_CSV  = 'C:\path\to\MachineLearningCVE\Friday-DDoS.csv'

venv\Scripts\python -m evaluation.eval_detection --limit 40000   # benchmark on the active dataset
```
Each adapter maps the dataset's attack labels to behavioural descriptions that
steer MITRE attribution (e.g. *DoS → "denial-of-service flood" → T1498*,
*Heartbleed → "public-facing service exploit" → T1190*). Bundled synthetic
samples (`evaluation/data/{unsw,cic}_sample.csv`) let the adapters' tests run
without the gated downloads. Adding ToN_IoT / live Zeek/NetFlow is just one more
adapter module with the same interface.

## Project layout
```
omnishield/      backend package (modular)
evaluation/      research harnesses + labeled data + results
frontend/        React/Vite dashboard
main.py          uvicorn entrypoint (uvicorn main:app)
requirements.txt / .env.example / frontend/.env.example
```

## Limitations
- The live stream is simulated/replayed, not raw packet capture.
- SOAR isolation is Windows-only (PowerShell firewall cmdlets) and needs admin.
- The frontend API key is a dev convenience; production needs real user auth.
