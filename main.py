"""OmniShield backend entrypoint.

The implementation now lives in the ``omnishield`` package (split by concern:
config, db, datasets, detection, mitre, llm, soar, api). This file is kept as a
thin, backwards-compatible entrypoint so existing run commands keep working:

    uvicorn main:app --reload
    # or
    python main.py
"""

from omnishield.api import app  # re-exported so `uvicorn main:app` still works

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
