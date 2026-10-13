"""``sp-rtk-portal``: run the Portal with uvicorn. Logs go to stdout.

Configuration comes from ``PORTAL_*`` environment variables (see
``config.Settings.from_env``). ``PORTAL_HOST``/``PORTAL_PORT`` set the listen
address (default ``0.0.0.0:8000``).
"""

from __future__ import annotations

import logging
import os
import sys

import uvicorn

from sp_rtk_portal.app import create_app
from sp_rtk_portal.config import Settings

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def configure_logging() -> None:
    logging.basicConfig(
        stream=sys.stdout,
        level=os.environ.get("PORTAL_LOG_LEVEL", "INFO").upper(),
        format=LOG_FORMAT,
        force=True,
    )


def main() -> None:
    configure_logging()
    app = create_app(Settings.from_env())
    uvicorn.run(
        app,
        host=os.environ.get("PORTAL_HOST", "0.0.0.0"),
        port=int(os.environ.get("PORTAL_PORT", "8000")),
        log_config=None,  # use the stdout handler set up above
        proxy_headers=False,  # the client IP comes from CF-Connecting-IP
    )


if __name__ == "__main__":
    main()
