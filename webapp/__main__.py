"""Convenience entrypoint with a non-standard default port to avoid conflicts."""

import os
from typing import Optional

import uvicorn

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def _as_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no"}


def main() -> None:
    host = os.getenv("UVICORN_HOST", DEFAULT_HOST)
    port = int(os.getenv("UVICORN_PORT", os.getenv("PORT", DEFAULT_PORT)))
    reload_enabled = _as_bool(os.getenv("UVICORN_RELOAD"), default=True)

    uvicorn.run("webapp.main:app", host=host, port=port, reload=reload_enabled)


if __name__ == "__main__":
    main()
