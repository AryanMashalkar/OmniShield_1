"""Next-Move Predictor — an ATT&CK kill-chain forecast (the agentic/graph layer).

Given the MITRE technique OmniShield just attributed to a live anomaly, this
predicts the adversary's *likely next stages* by walking the ATT&CK tactic
kill-chain graph forward. It answers PS#7's "predicts likely next-stage moves"
directly, and it is deterministic + explainable (a graph over ATT&CK tactics,
not a black box) — no training required.

The graph is the canonical Enterprise ATT&CK tactic ordering; each technique is
placed on it via its ``kill_chain_phases`` (already parsed in ``mitre.py``).
"""

from __future__ import annotations

# Canonical Enterprise ATT&CK tactic order (kill chain). Names match the
# space-form tactic strings produced by mitre._tactics().
TACTIC_ORDER = [
    "reconnaissance",
    "resource development",
    "initial access",
    "execution",
    "persistence",
    "privilege escalation",
    "defense evasion",
    "credential access",
    "discovery",
    "lateral movement",
    "collection",
    "command and control",
    "exfiltration",
    "impact",
]

# Flagship techniques per tactic — the high-signal moves a defender should
# pre-stage detections/containment for at each predicted next stage.
FLAGSHIP = {
    "reconnaissance": [("T1595", "Active Scanning"), ("T1592", "Gather Victim Host Information"), ("T1589", "Gather Victim Identity Information")],
    "resource development": [("T1583", "Acquire Infrastructure"), ("T1587", "Develop Capabilities"), ("T1608", "Stage Capabilities")],
    "initial access": [("T1190", "Exploit Public-Facing Application"), ("T1566", "Phishing"), ("T1133", "External Remote Services")],
    "execution": [("T1059", "Command and Scripting Interpreter"), ("T1203", "Exploitation for Client Execution"), ("T1053", "Scheduled Task/Job")],
    "persistence": [("T1547", "Boot or Logon Autostart Execution"), ("T1136", "Create Account"), ("T1505", "Server Software Component")],
    "privilege escalation": [("T1068", "Exploitation for Privilege Escalation"), ("T1055", "Process Injection"), ("T1548", "Abuse Elevation Control Mechanism")],
    "defense evasion": [("T1070", "Indicator Removal"), ("T1027", "Obfuscated Files or Information"), ("T1112", "Modify Registry")],
    "credential access": [("T1110", "Brute Force"), ("T1003", "OS Credential Dumping"), ("T1555", "Credentials from Password Stores")],
    "discovery": [("T1046", "Network Service Discovery"), ("T1018", "Remote System Discovery"), ("T1082", "System Information Discovery")],
    "lateral movement": [("T1021", "Remote Services"), ("T1210", "Exploitation of Remote Services"), ("T1570", "Lateral Tool Transfer")],
    "collection": [("T1005", "Data from Local System"), ("T1114", "Email Collection"), ("T1560", "Archive Collected Data")],
    "command and control": [("T1071", "Application Layer Protocol"), ("T1105", "Ingress Tool Transfer"), ("T1572", "Protocol Tunneling")],
    "exfiltration": [("T1041", "Exfiltration Over C2 Channel"), ("T1048", "Exfiltration Over Alternative Protocol"), ("T1567", "Exfiltration Over Web Service")],
    "impact": [("T1486", "Data Encrypted for Impact"), ("T1498", "Network Denial of Service"), ("T1490", "Inhibit System Recovery")],
}

# One-line defensive priority per next tactic (shown with the forecast).
TACTIC_DEFENCE = {
    "reconnaissance": "tighten external attack surface / rate-limit scanning",
    "resource development": "monitor for new attacker infrastructure and staged tooling",
    "initial access": "patch public-facing services; harden auth and email",
    "execution": "restrict script interpreters; enable EDR behavioural blocking",
    "persistence": "audit autostart/scheduled tasks and new accounts",
    "privilege escalation": "patch privesc CVEs; watch token/process injection",
    "defense evasion": "alert on log clearing and security-tool tampering",
    "credential access": "enforce MFA; monitor LSASS access and brute force",
    "discovery": "watch internal scanning and account/host enumeration",
    "lateral movement": "segment the network; monitor RDP/SMB/WMI usage",
    "collection": "DLP on sensitive shares; alert on bulk archive creation",
    "command and control": "egress-filter and inspect beaconing / tunnels",
    "exfiltration": "block large outbound transfers to untrusted destinations",
    "impact": "isolate now; verify backups and recovery readiness",
}

_tech_tactics: dict[str, list[str]] | None = None
_tech_name: dict[str, str] | None = None


def _load() -> None:
    global _tech_tactics, _tech_name
    if _tech_tactics is not None:
        return
    from .mitre import load_mitre_documents

    _tech_tactics = {}
    _tech_name = {}
    for doc in load_mitre_documents():
        tid = doc.metadata.get("id")
        if not tid:
            continue
        tactics = [t.strip() for t in (doc.metadata.get("tactics") or "").split(",") if t.strip()]
        _tech_tactics[tid] = tactics
        _tech_name[tid] = doc.metadata.get("name")


def _current_index(technique_id: str) -> int | None:
    _load()
    tactics = _tech_tactics.get(technique_id) or []
    idxs = [TACTIC_ORDER.index(t) for t in tactics if t in TACTIC_ORDER]
    # Use the earliest tactic the technique belongs to, so we forecast forward.
    return min(idxs) if idxs else None


def predict_next_moves(technique_id: str, horizon: int = 2) -> dict:
    """Forecast the adversary's next kill-chain stages after ``technique_id``.

    Returns a JSON-serialisable dict:
        {
          technique_id, technique_name, known, current_tactic, terminal,
          message,
          predictions: [{tactic, defence, techniques: [{id, name}]}]
        }
    """
    _load()
    tid = (technique_id or "").upper().strip()
    name = _tech_name.get(tid)
    idx = _current_index(tid)

    if idx is None:
        return {
            "technique_id": tid,
            "technique_name": name,
            "known": False,
            "current_tactic": None,
            "terminal": False,
            "message": "Technique not mapped in the ATT&CK knowledge base — manual analyst review advised.",
            "predictions": [],
        }

    current_tactic = TACTIC_ORDER[idx]

    if idx >= len(TACTIC_ORDER) - 1:
        return {
            "technique_id": tid,
            "technique_name": name,
            "known": True,
            "current_tactic": current_tactic,
            "terminal": True,
            "message": "Terminal 'Impact' stage reached — this IS the objective. "
            "Prioritise immediate isolation, and verify backup / recovery readiness.",
            "predictions": [],
        }

    predictions = []
    for tactic in TACTIC_ORDER[idx + 1 : idx + 1 + horizon]:
        predictions.append(
            {
                "tactic": tactic,
                "defence": TACTIC_DEFENCE.get(tactic, ""),
                "techniques": [{"id": i, "name": n} for i, n in FLAGSHIP.get(tactic, [])],
            }
        )

    return {
        "technique_id": tid,
        "technique_name": name,
        "known": True,
        "current_tactic": current_tactic,
        "terminal": False,
        "message": f"Attacker is at the '{current_tactic}' stage; likely next moves forecast below.",
        "predictions": predictions,
    }
