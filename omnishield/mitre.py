"""MITRE ATT&CK Enterprise knowledge base loading.

Parses the cached STIX bundle into LangChain ``Document`` objects (top-level
techniques only) for embedding into the vector store used by RAG attribution.

Each document is enriched for retrieval quality: the technique's tactic(s) and a
cleaned, fuller description are embedded alongside the ID and name, so a natural-
language anomaly description ("thousands of failed logins against the VPN") lands
near the right technique ("Brute Force", tactic: credential access) instead of a
sparse ID+first-line stub.
"""

import json
import os
import re
import urllib.request

from langchain_core.documents import Document

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
MITRE_CACHE_FILE = "mitre_attack_cache.json"
# High enough to cover every top-level Enterprise technique (~200). Sub-techniques
# (IDs containing ".") are rolled up to their parent and skipped below.
MAX_TECHNIQUES = 2000
# Cap embedded description length so one long technique can't dominate an embedding.
MAX_DESC_CHARS = 600

FALLBACK_MITRE_DOCS = [
    Document(
        page_content="Technique ID: T1566 - Phishing. Adversaries send phishing "
        "messages to gain access to victim systems via social engineering, "
        "spearphishing attachments, or malicious links.",
        metadata={"id": "T1566", "name": "Phishing"},
    ),
    Document(
        page_content="Technique ID: T1041 - Exfiltration Over C2 Channel. "
        "Adversaries steal data by transferring it through an established "
        "command and control channel, causing unexpected outbound bandwidth spikes.",
        metadata={"id": "T1041", "name": "Exfiltration Over C2"},
    ),
    Document(
        page_content="Technique ID: T1059 - Command and Scripting Interpreter. "
        "Adversaries execute commands or scripts through PowerShell or Cmd to "
        "bypass administrative controls.",
        metadata={"id": "T1059", "name": "Scripting Interpreter Execution"},
    ),
    Document(
        page_content="Technique ID: T1078 - Valid Accounts. Adversaries compromise "
        "existing credentials to gain unauthorized access to internal systems and "
        "database endpoints.",
        metadata={"id": "T1078", "name": "Valid Accounts"},
    ),
]

_CITATION_RE = re.compile(r"\(Citation:.*?\)", re.DOTALL)
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_CODE_RE = re.compile(r"<code>(.*?)</code>", re.DOTALL)
_WS_RE = re.compile(r"\s+")


def _clean_description(text: str) -> str:
    """Strip MITRE's citation markup / markdown / HTML into clean prose."""
    if not text:
        return ""
    text = _CITATION_RE.sub("", text)
    text = _CODE_RE.sub(r"\1", text)
    text = _MD_LINK_RE.sub(r"\1", text)
    text = text.replace("*", "").replace("`", "")
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > MAX_DESC_CHARS:
        text = text[:MAX_DESC_CHARS].rsplit(" ", 1)[0] + "..."
    return text


def _tactics(obj: dict) -> list[str]:
    """Human-readable tactic names from the STIX kill_chain_phases."""
    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            name = phase.get("phase_name", "").replace("-", " ").strip()
            if name and name not in tactics:
                tactics.append(name)
    return tactics


def fetch_mitre_stix_bundle() -> dict:
    if os.path.exists(MITRE_CACHE_FILE):
        with open(MITRE_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    print("[OmniShield] Downloading MITRE ATT&CK Enterprise dataset (first run only)...")
    with urllib.request.urlopen(MITRE_ATTACK_URL, timeout=60) as response:
        data = json.loads(response.read().decode("utf-8"))

    with open(MITRE_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)

    return data


def load_mitre_documents() -> list[Document]:
    try:
        bundle = fetch_mitre_stix_bundle()
    except Exception as e:
        print(f"[WARNING] Could not fetch MITRE ATT&CK dataset ({e}). Using fallback set.")
        return FALLBACK_MITRE_DOCS

    docs: list[Document] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        attack_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break

        if not attack_id or "." in attack_id:
            continue

        name = obj.get("name", "Unknown Technique")
        description = _clean_description(obj.get("description") or "")
        tactics = _tactics(obj)
        tactic_line = f" Tactics: {', '.join(tactics)}." if tactics else ""

        # Rich, retrieval-friendly text: ID, name, tactic(s), then clean prose.
        page_content = (
            f"Technique {attack_id}: {name}.{tactic_line} {description}"
        ).strip()

        docs.append(
            Document(
                page_content=page_content,
                metadata={"id": attack_id, "name": name, "tactics": ", ".join(tactics)},
            )
        )

        if len(docs) >= MAX_TECHNIQUES:
            break

    if not docs:
        print("[WARNING] Parsed 0 MITRE techniques. Using fallback set.")
        return FALLBACK_MITRE_DOCS

    print(f"[OmniShield] Loaded {len(docs)} real MITRE ATT&CK techniques.")
    return docs
