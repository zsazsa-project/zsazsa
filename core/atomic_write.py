"""Replace a file in one step.

Several files here are written by the web app and read by the analyser, or the
other way round, from separate processes: the analyser state, the AI feature
settings, the configuration module itself. Opening one for writing truncates it
first, so a reader arriving in that window sees an empty file and falls back to
its defaults, and a writer that read it that way can save its own keys over a
state it never really read. Writing beside the file and renaming leaves readers
with either the old version or the new one.
"""

import os
import tempfile
from pathlib import Path


def write_atomically(path, text: str) -> None:
    """Write ``text`` to ``path``, replacing it only once fully written."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
