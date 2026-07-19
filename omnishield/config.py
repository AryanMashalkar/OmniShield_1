"""Centralised, environment-driven configuration.

Every tunable and every secret is read from the environment (optionally via a
local ``.env`` file). Nothing sensitive is hard-coded. This is the fix for the
previous "hardcoded dev key + CORS=*" security posture.
"""

import os
import secrets

try:
    # python-dotenv is a dependency; load a local .env if present.
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional at runtime
    pass


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Settings:
    """Runtime configuration resolved from the environment."""

    def __init__(self) -> None:
        # --- Auth -----------------------------------------------------------
        # No insecure hard-coded default. If the operator does not supply a
        # key we generate a random one per-process and print it once, so the
        # secret is never committed to source or shipped in a build.
        self.api_key: str = os.environ.get("OMNISHIELD_API_KEY", "").strip()
        self._api_key_was_generated = False
        if not self.api_key:
            self.api_key = secrets.token_urlsafe(24)
            self._api_key_was_generated = True

        # --- CORS -----------------------------------------------------------
        # Comma-separated allow-list. Defaults to the local Vite dev server
        # instead of the previous wildcard "*".
        origins = os.environ.get(
            "OMNISHIELD_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        )
        self.cors_origins: list[str] = [o.strip() for o in origins.split(",") if o.strip()]

        # --- Models ---------------------------------------------------------
        self.llm_model: str = os.environ.get("OMNISHIELD_LLM_MODEL", "llama3.1:8b")
        self.embed_model: str = os.environ.get("OMNISHIELD_EMBED_MODEL", "nomic-embed-text")

        # --- Storage --------------------------------------------------------
        self.db_path: str = os.environ.get("OMNISHIELD_DB_PATH", "omnishield.db")
        self.chroma_dir: str = os.environ.get("OMNISHIELD_CHROMA_DIR", "./chroma_db_mitre")

        # --- Detection ------------------------------------------------------
        self.baseline_window_size: int = _get_int("OMNISHIELD_BASELINE_WINDOW", 40)
        self.anomaly_z_threshold: float = _get_float("OMNISHIELD_Z_THRESHOLD", 3.0)
        self.min_baseline_samples: int = _get_int("OMNISHIELD_MIN_BASELINE", 10)

        # --- Live stream ----------------------------------------------------
        # "simulate" = NSL-KDD normal samples + scripted exfil (original demo).
        # "replay"   = replay real labeled NSL-KDD records (incl. attacks).
        self.stream_mode: str = os.environ.get("OMNISHIELD_STREAM_MODE", "simulate").lower()
        self.stream_interval: float = _get_float("OMNISHIELD_STREAM_INTERVAL", 2.0)

        # --- SOAR human-in-the-loop policy ---------------------------------
        # When True, /api/block-ip requires an explicit analyst confirmation
        # token (the "human in the loop"). This formalises the safe-autonomy
        # design: the AI recommends, a human authorises, the system acts.
        self.soar_require_confirmation: bool = _get_bool(
            "OMNISHIELD_SOAR_REQUIRE_CONFIRMATION", True
        )

    def warn_if_insecure(self) -> None:
        if self._api_key_was_generated:
            print(
                "\n[OmniShield] OMNISHIELD_API_KEY was not set. A random key was "
                "generated for this session:\n"
                f"    {self.api_key}\n"
                "    Set OMNISHIELD_API_KEY (and VITE_OMNISHIELD_API_KEY for the "
                "frontend) to a stable value for real use.\n"
            )
        if "*" in self.cors_origins:
            print("[OmniShield][WARNING] CORS is set to '*'. Do not use in production.")


settings = Settings()
