# OmniShield — 3-4 Minute Demo Video Script

**Problem Statement 7: AI-Driven Cyber Resilience for Critical National Infrastructure**

---

## ⚠ Pre-flight (do this BEFORE you hit record)

1. **Make the CIC claim true.** Point the demo at the *real* CIC-IDS-2017 data:
   ```powershell
   python scripts\prepare_cic.py "path\to\MachineLearningCVE"      # the real gated download
   $env:OMNISHIELD_DATASET='cic_ids'; $env:OMNISHIELD_CIC_CSV='A:\OmniShield\cic_ids2017.csv'
   $env:OMNISHIELD_STREAM_MODE='replay'
   $env:OMNISHIELD_API_KEY = (Get-Content .\frontend\.env | Select-String 'VITE_OMNISHIELD_API_KEY=(.*)').Matches.Groups[1].Value
   .\venv\Scripts\uvicorn.exe main:app
   ```
   > **If you have NOT downloaded the real CIC CSV:** use the ⟨fallback⟩ wording marked in the
   > script and run with the bundled sample (`OMNISHIELD_CIC_CSV=evaluation\data\cic_sample.csv`).
   > Never say "authentic" / "real" CIC on camera unless the real file is loaded.
2. Warm Ollama (`ollama run llama3.1:8b` once) so attribution is snappy.
3. Frontend up (`npm run dev --prefix frontend`) → open **http://localhost:5173**, hard-refresh (Ctrl+Shift+R).
4. Let the stream run ~30s before recording so the accuracy counter and an incident have populated.
5. Read your **actual** on-screen accuracy number instead of the placeholder.

---

## THE SCRIPT  (~3:45)

### [0:00 – 0:20] Hook
*[Screen: full OmniShield dashboard, header pulsing "LIVE TELEMETRY ACTIVE" in green]*

> "When AIIMS Delhi was hit by ransomware, a national hospital was down for **two weeks** — and the
> warning signs were in the logs the whole time. The problem isn't missing data. It's that today's
> Security Operations Centers are **reactive** — static rules, known signatures, always one step
> behind. **OmniShield** flips that: a *predictive, agentic* SOC. And it's running live, right now."

### [0:20 – 0:55] The Data Differentiator
*[Point to the packet stream scrolling; point to the "Detection: z-score + IsolationForest" tag]*

> "Most projects still benchmark on NSL-KDD — **synthetic traffic from 1998**. We don't. This is a
> live WebSocket stream of **CIC-IDS-2017** — authentic modern enterprise traffic, with the threats a
> real SOC actually faces."
> *[Point to the ground-truth chips in the rows: "truth: Heartbleed", "truth: DDoS", "truth: PortScan"]*
> "Heartbleed. Botnets. DDoS. Slowloris. Every flow is scored the **instant** it arrives."
>
> ⟨**Fallback if real CIC not loaded:**⟩ *"...a live stream of modern **CIC-IDS-2017-format** enterprise
> flows — Heartbleed, Botnets, DDoS, Slowloris — through a fully pluggable dataset engine."*

### [0:55 – 1:35] The ML Engine
*[Point to a red "THREAT · IForest" row showing 0 Bytes; then up to the header "Detection accuracy 94%"]*

> "Detection is **behavioural**, not signature-based. A multivariate **IsolationForest** trains on the
> baseline of normal flows — and, critically, it learns a profile **per host**. So a zero-byte
> port-scan a static threshold would miss? *[point]* Flagged — because it's abnormal *for that host*.
> And we're honest about it: watch the header — we score ourselves **live against ground truth**.
> *[point to accuracy]* ~94% accuracy, **sub-second** detection. Our F1 went from 0.15 on a univariate
> model to **0.93**."

### [1:35 – 2:10] Active Incident Correlation
*[Scroll to the "Active Incidents · correlated by host" panel; point to the host 192.168.1.66 card]*

> "Real attacks are noisy — dozens of weak signals. Instead of burying the analyst in red rows,
> OmniShield **correlates them by source host** into a single incident. Look at this host — it isn't
> ten random alerts. It's **one story**: *[trace the chain]* Discovery → Credential Access → Lateral
> Movement. One host, one campaign. That's how you defeat alert fatigue."

### [2:10 – 3:00] The Innovation — Next-Move Predictor
*[Click an active anomaly to escalate; the "AI Threat Intelligence" panel resolves — point to the MITRE technique + confidence, then to "Predicted Attacker Next Moves"]*

> "Now the intelligence. Our **local Llama 3.1**, grounded in the **MITRE ATT&CK** framework via RAG,
> maps the behaviour to a technique — on-box, in seconds, **nothing leaving the perimeter**."
> *[point to Next Moves section]*
> "But here's our innovation. We don't stop at *what's happening* — we predict **what's next**. This
> attacker is at *Discovery*; our kill-chain graph forecasts **Lateral Movement** as the next stage,
> so we can pre-stage containment **before** it happens. And when it's a flood — *[gesture]* — it flags
> the **Terminal Impact** stage: *'this is the objective, isolate now.'* We get **ahead** of the
> attacker instead of chasing them."

### [3:00 – 3:40] SOAR Isolation
*[Hover the red "EXECUTE SOAR ISOLATION" button, then click it; status flips to NEUTRALIZED; scroll to the Incident Log]*

> "So we act. **One click** — *[click]* — and OmniShield executes a SOAR playbook: it injects a
> firewall rule, isolates the malicious IP, and the threat is **neutralized**. But the AI never pulls
> the trigger alone — it *recommends*; a *human authorizes*. And every action is **logged** —
> *[point to Incident Log]* auditable, reversible, court-ready. Detect, predict, contain — in **under
> a minute**, entirely on-prem."

### [3:40 – 3:55] Close
*[Return to the full dashboard, status green "SECURE"]*

> "That's OmniShield: behavioural detection, MITRE-grounded attribution, next-move **prediction**, and
> human-gated response — running **entirely on local hardware**, so a hospital or a power grid never
> ships a single byte to the cloud. We don't just watch the breach. We get **ahead** of it. Thank you."

---

## Delivery tips
- **Energy up, pace steady.** Hit the bold words. Pause a beat after "what's next" — that's your wow moment.
- **Point, don't read.** The brackets tell you where to move the cursor; keep your eyes on the screen action.
- **Record in 1080p**, cursor highlight on, mic close. Keep it under 4:00 — aim for 3:45.
- **One clean take of the click-to-isolate** — if the firewall call needs admin, run the backend as Administrator so NEUTRALIZED lands on camera.
