"""Logging for the command-line entry points.

run_analyser.py and run_imap_collector.py are both run from cron and want the
same thing: the rotating file the web app writes to, plus console output so a
manual run shows progress. The web app configures its own logging in
webapp.create_app, where handlers must not be added twice per worker.
"""

import logging
import logging.handlers
from pathlib import Path

import config

_MAX_BYTES = 5 * 1024 * 1024
_BACKUP_COUNT = 3


def setup_logging() -> None:
    """Send the root logger to the rotating log file and to the console."""
    Path(config.LOG_FILE).parent.mkdir(exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    root = logging.getLogger()
    root.setLevel(getattr(logging, config.LOG_LEVEL))

    file_handler = logging.handlers.RotatingFileHandler(
        config.LOG_FILE, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)
