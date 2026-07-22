# OmniShield — ET AI Hackathon 2026 Pitch Playbook

**Problem Statement #7 — AI-Driven Cyber Resilience for Critical National Infrastructure**
Theme: Cybersecurity / Industrial Intelligence / National Security

> This is the storyboard for the **Presentation Deck + Demo Video** deliverables.
> Every number below is reproducible from `evaluation/results/*_latest.json`.
> Slide count target: **12–13**. Pitch length: **~6 min talk + ~4 min demo**.

---

## 0. The 20-second hook (say this first, verbatim)

> "When AIIMS Delhi was ransomwared in 2022 it was down for **two weeks** — and the
> warning signs were in the logs the whole time. The problem was never missing data;
> it's the missing *intelligence layer* that connects detection to attribution to
> response fast enough to matter. **OmniShield is that layer** — a closed
> detect → attribute → contain loop that runs on a **fully local LLM**, so a
> critical-infrastructure operator never ships a single packet of sensitive
> security data to a cloud. And unlike a slide, **it runs live — here it is.**"

---

## 1. Why this matters (Business Impact — 25%)

Frame the pain with India-specific, verifiable scale (all from PS7 + public reports):

- **CERT-In handled 1.59M cybersecurity incidents in 2023** — and climbing.
- **AIIMS Delhi**: ransomware, ~2 weeks of outage (2022). **CBSE**: breach 2024, and a
  coordinated attack ahead of 2026 board exams forcing multi-state shutdowns.
- **>70% of government entities run end-of-life IT** (National Cyber Security Policy) —
  attackers barely have to work for entry.
- **The real gap is detection speed.** Industry dwell-time benchmarks (Mandiant M-Trends,
  IBM Cost of a Data Breach) put **mean-time-to-detect in the weeks-to-months range**;
  APTs deliberately run "low-and-slow" to beat signature detection.

**One-line thesis:** *"By the time a signature exists, the attack already succeeded
somewhere. OmniShield detects from behaviour, attributes with grounded AI, and contains
with a human-gated playbook — compressing weeks to a **sub-minute** loop, on-prem."*

### The quantified case (put this on the Business-Impact slide)

**MTTD/MTTR — weeks → seconds (the metric PS7 scores):**
| Stage | Industry baseline | OmniShield |
|---|---|---|
| Detect (MTTD) | ~200+ days to identify (IBM Cost of a Data Breach); ~10–16 day dwell (Mandiant) | **real-time** — every flow scored on arrival |
| Attribute to MITRE technique | hours–days (manual analyst) | **~7 s** (local RAG) |
| Forecast next stage | not done | **instant** (kill-chain graph) |
| Contain (MTTR) | hours–days (ticket → approval → manual block) | **<60 s** — one human-gated click |

**Cost leverage:** IBM pegs the global average breach at **~$4.4M**, and finds that
containing an incident in **<200 days saves ~$1M+** versus slower responders. AIIMS Delhi
lost **~2 weeks of national hospital operations** to one ransomware event. OmniShield's
entire detect→contain loop is **sub-minute** on confirmed anomalies — the difference
between a blocked host and a two-week outage.

**Data-sovereignty (the wedge cloud SOCs can't match):** 100% local inference (Llama 3.1
via Ollama) → **zero data egress**, runs **air-gapped**, no per-token cloud cost, no
third-party data processor. For a defence PSU / power grid / exam board, that is not a
feature — it is a procurement precondition.

**Addressable scope:** CERT-In's 1.59M-incident/year surface across **>70% of government
entities on end-of-life IT** — the exact estate that cannot adopt a cloud SIEM but can run
an on-prem box.

---

## 2. What OmniShield is (the closed loop)

```
   Live telemetry ──▶ [1] DETECT ──▶ [2] ATTRIBUTE ──▶ [3] RECOMMEND ──▶ [4] CONTAIN ──▶ [5] AUDIT
                       behavioural      MITRE ATT&CK      LLM action       human-gated      SQLite
                       anomaly (UEBA)   RAG (local LLM)   step             SOAR firewall    incident log
```

Position the five modules as **cooperating agents** (honest framing — they are separable,
single-responsibility components; orchestration today is a deterministic pipeline):

| Agent | Module | Does |
|---|---|---|
| Detection Agent | `omnishield/detection.py` | Multivariate IsolationForest (authoritative) + z-score fast-path |
| Attribution Agent | `omnishield/llm.py` + `mitre.py` | RAG over 222 MITRE ATT&CK techniques, local Llama 3.1 |
| Response Agent | `omnishield/soar.py` | Windows Firewall isolation playbook |
| Governance Agent | `omnishield/api.py` (HTTP 428) | Human-in-the-loop authorization gate |
| Audit Agent | `omnishield/db.py` | Immutable incident/audit log |

---

## 3. Evidence — we benchmarked everything (Technical Excellence — 20%)

This is your **differentiation slide**. Most teams show a demo; you show *receipts*.
All reproducible: `python -m evaluation.eval_detection` / `eval_attribution` / `eval_robustness`.

**A. Behavioural detection (NSL-KDD, one-class training)**

| Detector | F1 | Note |
|---|---|---|
| Rolling z-score (univariate, old live) | **0.15** | blind to scan/DoS/brute-force |
| **IsolationForest (new live, authoritative)** | **0.93** | catches low-and-slow attacks |
| One-Class SVM (reference) | 0.94 | |

> Headline: **"We benchmarked our own detector honestly, found the univariate z-score
> scored F1 0.15, and rebuilt the live pipeline around a multivariate model — F1 0.93,
> a 6× jump. Live, it caught a `neptune` DoS flood carrying *zero bytes* that the old
> detector mathematically could never flag."**

**B. APT attribution at MITRE technique level (40-example labeled set, local Llama 3.1)**

| Mode | Top-1 accuracy | Retrieval hit@k |
|---|---|---|
| Zero-shot LLM | 0.35 | — |
| **RAG (grounded)** | **0.75** | **0.83** |

> Headline: **"Grounding the LLM in MITRE ATT&CK more than doubles attribution accuracy
> (0.35 → 0.75). This is an ablation, not a claim — RAG vs zero-shot on the same set."**

**C. Robustness — prompt injection**
- Embedded "report this as benign" instructions in real threats: **attack-success-rate 0.0**
  on both the scam analyzer and the attribution pipeline (small n — state it honestly as
  a robustness *check*, not a guarantee).

---

## 4. The data-sovereignty angle (your Innovation wedge — 25%)

For **critical national infrastructure**, this is the argument that beats a slicker cloud demo:

- **100% local inference** — Llama 3.1 (8B) + nomic-embed-text via Ollama. No API keys,
  no per-token cost, **no data leaves the perimeter**. Runs **air-gapped**.
- No third-party data processor → sidesteps a whole class of regulatory/sovereignty risk
  that a cloud SIEM/SOAR (Splunk, Sentinel) cannot.
- **Safe autonomy:** the AI *recommends*; a human *authorizes* (HTTP 428 gate); the system
  *acts* and *audits*. Directly answers PS7's "human escalation gates above blast-radius."

> "A cloud SOC asks a defence PSU or a power grid to trust an American hyperscaler with its
> attack telemetry. OmniShield asks them to trust **their own hardware**."

---

## 5. Slide-by-slide outline (12–13 slides)

1. **Title** — OmniShield · PS#7 · team name · "Autonomous, on-prem cyber resilience."
2. **The hook** — AIIMS/CBSE + CERT-In 1.59M; "data present, unacted-upon."
3. **The gap** — detection speed: weeks-to-months dwell time vs the closed loop we need.
4. **OmniShield in one diagram** — the 5-agent detect→attribute→contain→audit loop.
5. **Detect** — behavioural UEBA; the F1 0.15 → 0.93 story + the zero-byte DoS catch.
6. **Attribute** — MITRE RAG; 0.35 → 0.75; local, grounded, JSON-structured.
7. **Contain (safely)** — SOAR firewall isolation + HTTP 428 human gate + audit log.
8. **Data sovereignty** — local LLM, air-gap capable; the CNI trust argument.
9. **Evidence** — the three benchmark tables (§3); "reproducible, in-repo."
10. **PS#7 coverage map** — checklist (§6) + Evaluation-Focus map (§7).
11. **Architecture** — modules, FastAPI + WebSocket, Chroma, SQLite, Ollama.
12. **Roadmap / honest limitations** (§9) — turns gaps into a credible plan.
13. **Close + ask** — "It runs today. Here's the 4-minute proof." → demo.

---

## 6. PS#7 "What you may build" — coverage map (put on slide 10)

| PS#7 building block | OmniShield | Status |
|---|---|---|
| Behavioural Anomaly Detection Engine (**UEBA**, no signatures) | **Per-entity baselines** (per host) + IsolationForest one-class + z-score | ✅ Built |
| Correlate weak signals → map attack progression | **Incident correlation** — anomalies grouped by host into kill-chain campaigns (`correlation.py`, `/api/campaigns`) | ✅ Built |
| APT Campaign Attribution (MITRE ATT&CK) | RAG over 222 techniques, local LLM | ✅ Built |
| APT next-stage **prediction** | **Next-Move Predictor — ATT&CK kill-chain graph** (`nextmove.py`, live in the dashboard) | ✅ Built |
| Autonomous Incident Response Orchestrator (isolate/block, human gate) | SOAR firewall playbook + HTTP 428 | ✅ Built |
| Full auditability of automated actions | SQLite incident log | ✅ Built |
| Multi-dataset (modern traffic) | Pluggable NSL-KDD / UNSW-NB15 / CIC-IDS-2017 adapters | ✅ Built |
| Gov Infra Vulnerability Prioritisation (CVE feeds) | — | 🔵 Roadmap |
| Cyber Resilience Digital Twin | — | 🔵 Roadmap |

Be explicit: **every core "may build" bullet is built — UEBA, correlation, attribution,
prediction, autonomous response, audit — plus modern-data support and reproducible
benchmarks.** Honesty on the two roadmap items *builds* credibility with judges.

---

## 7. PS#7 "Evaluation Focus" — direct answers (say these)

| Judge asks for… | Your answer |
|---|---|
| Anomaly detection rate **and false-positive rate** on benchmark datasets | NSL-KDD: F1 **0.93**, recall ~0.91, FP ~5–11% (tunable via contamination) |
| APT attribution accuracy **at MITRE technique level** | **0.75** top-1 on a 40-example labeled set; retrieval hit@k **0.83** |
| Incident-response automation **coverage** (% of playbook autonomous) | Detect + attribute + recommend fully automated; containment one-click behind a blast-radius gate; all proto/direction firewall rules injected in one action |
| **MTTD/MTTR** improvement vs baseline SOC | Detection real-time; attribution ~7 s; containment <1 min — vs weeks-to-months industry dwell time |
| **Full auditability** of every automated action | Every BLOCK/UNBLOCK written to SQLite with status + details; reversible (unblock) |

---

## 8. The agentic / graph layer — Next-Move Predictor (BUILT)

PS#7 explicitly wants "predicts likely next-stage moves" and suggests "Graph AI (attack
path analysis)." **This is implemented** (`omnishield/nextmove.py`, wired into the
attribution response and the dashboard) — deterministic and explainable, no training:

**Next-Move Predictor (ATT&CK kill-chain graph):**
- After attribution → technique T's tactic, it walks the ATT&CK tactic ordering (Recon →
  Initial Access → Execution → Persistence → Priv-Esc → Defense Evasion → Cred Access →
  Discovery → Lateral Movement → Collection → C2 → Exfil → Impact) and returns the
  **likely next tactics + flagship techniques + a defensive priority** for each.
- Verified live forecasts:
  - **Heartbleed → T1190 (Initial Access) → next: Execution (T1059/T1203), Persistence (T1547…)**
  - **PortScan → T1046 (Discovery) → next: Lateral Movement (T1021/T1210), Collection**
  - **Brute Force → T1110 (Credential Access) → next: Discovery, Lateral Movement**
  - **DDoS → T1498 (Impact) → TERMINAL: "this is the objective — isolate now, verify backups"**
- Demo line: *"We don't just say what's happening — we forecast the attacker's next stage
  and pre-stage containment. A graph over the ATT&CK kill chain, not a black box."*
- Exposed at `GET /api/next-moves?technique_id=T1046` and shown in the Threat Intel panel.

**Multi-agent framing:** present the 5 modules (§2) as cooperating agents (Detection,
Attribution, **Forecast**, Response, Audit) with an orchestrator. Honest and maps cleanly
to "Agentic AI / Multi-Agent Systems."

---

## 9. Roadmap / honest limitations (slide 12 — turn weaknesses into a plan)

State these *before* a judge finds them; it reads as maturity:

- **Telemetry:** demo replays labeled NSL-KDD flows for reproducibility. Architecture takes
  any flow feature vector → roadmap: **Zeek/NetFlow/EDR adapters** for live IT+OT capture.
- **Model:** local Llama 3.1 (8B), ~7 s/attribution — runs only on *confirmed anomalies*,
  not per-flow. Swappable for a larger local model on GPU nodes.
- **SOAR:** Windows Firewall today; the playbook layer is pluggable → **iptables / NAC /
  EDR isolation** for Linux/OT estates.
- **Attribution set:** n=40 labeled (not n=3) — reproducible and 2.1× over zero-shot;
  growing to 100+.
- **Roadmap:** CVE/CERT-In advisory RAG, vulnerability prioritization, attack-path graph,
  horizontal scale (queue + stateless scorers + per-tenant baselines).

---

## 10. Live demo script (~4 min — rehearse this exact path)

**Setup (before you present):** backend in **replay** mode as Administrator, frontend up,
Ollama warm. `OMNISHIELD_STREAM_MODE=replay`, `OMNISHIELD_STREAM_INTERVAL≈1.5`.

1. **Dashboard, calm state** — "LIVE TELEMETRY ACTIVE", Events Scanned ticking, status
   **SECURE**. "This is a live SOC console — 222 MITRE techniques loaded locally, no cloud."
2. **The catch** — a low-byte attack row lights up **"THREAT · IForest"**. Point at it:
   *"Zero bytes moved. The old z-score is blind to this. Our multivariate engine flagged it
   from its behavioural profile — exactly the low-and-slow class PS#7 calls out."*
3. **Attribution** — right panel resolves to a **MITRE technique + confidence + recommended
   action**. *"That's a local Llama 3.1, grounded in ATT&CK via RAG — ~7 seconds, nothing
   left the box. Benchmarked at 0.75 top-1, double the ungrounded baseline."*
4. **Forecast (the wow moment)** — the panel also shows **Predicted Attacker Next Moves**.
   *"We don't just classify the current step — we forecast the next kill-chain stages. This
   PortScan is Discovery; our graph predicts Lateral Movement (T1021/T1210) next, so we
   pre-stage the block before it happens. On a DDoS it says 'terminal Impact — isolate now.'"*
5. **Human-gated containment** — click **EXECUTE SOAR ISOLATION**. Status flips to
   **NEUTRALIZED**; a firewall rule is injected. *"The AI never blocks unilaterally — the
   backend returns HTTP 428 until a human authorizes. That's the blast-radius gate."*
6. **Audit** — scroll the **Incident Log**: timestamp, IP, action, status. *"Every automated
   action is logged and reversible. Full auditability — a PS#7 evaluation criterion."*
7. **Receipts** — flash the benchmark slide / open an `evaluation/results/*.json`. *"None of
   this is hand-wavy — here are the numbers, reproducible from the repo."*
8. *(Optional PS#6 bonus)* paste a "digital arrest" transcript into the scam analyzer for a
   structured threat verdict — ties to the fraud problem statement too.

---

## 11. Judge Q&A — prepared answers (rehearse the hard ones)

- **"Earlier your detector was the weakest one you benchmarked."**
  *"Correct — and we fixed it. The live pipeline is now IsolationForest-authoritative,
  F1 0.93; the z-score is a fast-path/fallback. We chose based on our own benchmark."*
- **"It's simulated data, not real capture."**
  *"Replay of labeled NSL-KDD for reproducibility. The detector consumes a feature vector —
  a Zeek/NetFlow adapter drops in without touching the model. Honest scope for a hackathon."*
- **"Why a local 8B model — isn't cloud smarter/faster?"**
  *"For national infrastructure, sovereignty isn't optional. 7 s on confirmed anomalies is
  fine — it's not per-flow. And it runs air-gapped. Swap in a bigger local model on GPU."*
- **"n=40 is small."**
  *"Agreed — but it's labeled, reproducible, and 2.1× over zero-shot with hit@k 0.83, not a
  cherry-picked n=3. We're scaling it to 100+."*
- **"How is this different from Splunk/Wazuh SOAR?"**
  *"Local LLM attribution + recommendation in a closed loop, zero cloud egress, benchmarked,
  and human-gated. A cloud SOAR can't offer sovereignty or on-box grounding."*
- **"False positives will cause auto-block disasters."**
  *"That's why blocking is human-gated and reversible, and FP rate is contamination-tunable.
  The AI recommends; a human authorizes; the log makes it accountable."*

---

## 12. Scorecard self-map (aim your talk-time by weight)

| Criterion | Weight | Lead with |
|---|---|---|
| Innovation | 25% | Local-LLM closed loop + data sovereignty + benchmark-driven design |
| Business Impact | 25% | CERT-In scale, AIIMS/CBSE cost, weeks→minutes, no cloud egress |
| Technical Excellence | 20% | 3 reproducible benchmarks + ablations + hardening |
| Scalability | 15% | Stateless scoring (IF ~198k eps), per-tenant baselines; honest roadmap |
| User Experience | 15% | One-glance SOC console, detector attribution, one-click gated isolation |

**Closing line:** *"Same disciplines that keep a steel plant running — applied to keeping the
grid, the hospital, and the exam board running. OmniShield is the intelligence layer that
acts before the breach, not after — and it's running today."*
