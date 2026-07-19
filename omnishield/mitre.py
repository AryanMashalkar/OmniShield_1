"""MITRE ATT&CK Enterprise knowledge base loading.

Parses the cached STIX bundle into LangChain ``Document`` objects (top-level
techniques only) for embedding into the vector store used by RAG attribution.
"""

import json
import os
import urllib.request

from langchain_core.documents import Document

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
MITRE_CACHE_FILE = "mitre_attack_cache.json"
MAX_TECHNIQUES = 250

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
        description = (obj.get("description") or "").split("\n")[0]

        docs.append(
            Document(
                page_content=f"Technique ID: {attack_id} - {name}. {description}",
                metadata={"id": attack_id, "name": name},
            )
        )

        if len(docs) >= MAX_TECHNIQUES:
            break

    if not docs:
        print("[WARNING] Parsed 0 MITRE techniques. Using fallback set.")
        return FALLBACK_MITRE_DOCS

    print(f"[OmniShield] Loaded {len(docs)} real MITRE ATT&CK techniques.")
    return docs
