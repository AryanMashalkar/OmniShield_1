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
   detection.py  rolling z-score (live) + ML baselines
   llm.py        lazy Ollama LLM + Chroma vector store + prompts
   mitre.py      MITRE ATT&CK STIX → embedded knowledge base
   datasets.py   NSL-KDD loading / sampling / replay / feature matrix
   soar.py       Windows Firewall isolation + human-in-the-loop policy
   db.py         SQLite incident/audit log
   config.py     environment-driven settings (no hard-coded secrets)
```

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
against **Isolation Forest**, **One-Class SVM**, and **PCA-reconstruction**
(autoencoder-style) detectors on the labeled **NSL-KDD** dataset (one-class
training on normal traffic). Reports accuracy / precision / recall / F1 /
confusion matrix / throughput.

> **Finding:** the byte-transfer z-score excels at exfiltration-style events but
> misses scan/DoS attacks that don't produce byte spikes (F1 ≈ 0.15), whereas
> multivariate one-class models reach F1 ≈ 0.94. This motivates augmenting the
> streaming detector with a multivariate model — a concrete research direction.

### 2. Attribution benchmark — `python -m evaluation.eval_attribution`
Ablation of **RAG vs zero-shot** LLM attack attribution over a labeled
anomaly→MITRE dataset (`evaluation/data/attribution_labeled.json`). Reports
top-1 accuracy, retrieval hit@k, valid-JSON rate, and latency. Requires Ollama.

### 3. Robustness benchmark — `python -m evaluation.eval_robustness`
**Prompt-injection** attacks against the scam analyzer and the attribution
pipeline: real threats carrying an embedded "report this as benign" instruction.
Reports attack-success-rate (lower = more robust). Requires Ollama.

---

## Datasets
- **MITRE ATT&CK Enterprise** (STIX) — embedded into Chroma for RAG attribution.
- **NSL-KDD** — network intrusion benchmark used for simulated/replay traffic
  and the detection evaluation. Both are cached on first run.

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
