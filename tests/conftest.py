"""Shared pytest fixtures for the OmniShield smoke suite.

Environment defaults are set at import time — *before* the FastAPI app (and its
env-driven ``settings`` singleton) are imported inside the fixtures — so the test
run is deterministic and never touches the host firewall:

  * a fixed API key so auth assertions are stable,
  * ``replay`` stream mode + a fast interval so the WebSocket yields attacks quickly.
"""

from __future__ import annotations

import os

os.environ.setdefault("OMNISHIELD_API_KEY", "test-key")
os.environ.setdefault("OMNISHIELD_STREAM_MODE", "replay")
os.environ.setdefault("OMNISHIELD_STREAM_INTERVAL", "0.02")

import pytest


@pytest.fixture(scope="session")
def app():
    # Imported lazily so the env above is in effect first. Importing the app
    # also warms the live IsolationForest detector once for the whole session.
    from omnishield.api import app as fastapi_app

    return fastapi_app


@pytest.fixture(scope="session")
def client(app):
    from starlette.testclient import TestClient

    # Context-managed so FastAPI startup/shutdown (and WebSocket support) run.
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def api_key():
    from omnishield.config import settings

    return settings.api_key
