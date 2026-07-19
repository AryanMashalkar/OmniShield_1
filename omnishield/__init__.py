"""OmniShield — AI-powered autonomous SOC platform.

This package contains the modular backend that was previously a single
``main.py`` file. Modules are split by concern so that the evaluation and
research harnesses can import the pieces they need (datasets, detectors)
without pulling in the heavy LLM / vector-store initialisation.
"""

__version__ = "1.0.0"
