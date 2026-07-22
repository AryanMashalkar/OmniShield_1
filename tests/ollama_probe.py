"""Ollama readiness probe used to skip LLM-dependent tests when Ollama is down.

Kept in its own module (not conftest) so both the fixtures and the individual
test modules can import the ``requires_ollama`` marker.
"""

from __future__ import annotations

import socket

import pytest


def _ollama_ready() -> bool:
    # Fast fail: is anything listening on the Ollama port?
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=1.5):
            pass
    except OSError:
        return False
    # Confirm the two models OmniShield needs are actually pulled.
    try:
        import ollama

        data = ollama.list()
        models = data.get("models") if isinstance(data, dict) else getattr(data, "models", [])
        names = []
        for m in models:
            name = m.get("model") if isinstance(m, dict) else getattr(m, "model", None)
            if name:
                names.append(name)
        blob = " ".join(names)
        return "llama3.1" in blob and "nomic-embed" in blob
    except Exception:
        return False


OLLAMA_AVAILABLE = _ollama_ready()

requires_ollama = pytest.mark.skipif(
    not OLLAMA_AVAILABLE,
    reason="Ollama not reachable / required models (llama3.1 + nomic-embed-text) not pulled",
)
