#!/bin/sh
# Container entrypoint: create config/__init__.py on first start, then run the
# given command.
#
# Mirrors step 5 of docs/install.sh: when no config exists, the example is
# copied with a freshly generated SECRET_KEY. An existing config is never
# touched. ZSAZSA_JOB_REDIS_HOST, when set, is written into JOB_REDIS_HOST of
# the generated file so background job state reaches the compose Redis service.
set -eu

python - <<'PY'
import os
import pathlib
import re
import secrets
import tempfile

target = pathlib.Path("config/__init__.py")
if not target.exists():
    text = pathlib.Path("/app/docker/config.example.py").read_text()
    text, count = re.subn(r"^SECRET_KEY = .*",
                          f"SECRET_KEY = {secrets.token_hex(32)!r}",
                          text, count=1, flags=re.M)
    if not count:
        raise SystemExit("config example has no SECRET_KEY line to replace")
    redis_host = os.environ.get("ZSAZSA_JOB_REDIS_HOST")
    if redis_host:
        text = re.sub(r"^JOB_REDIS_HOST = .*", f"JOB_REDIS_HOST = {redis_host!r}",
                      text, count=1, flags=re.M)
    target.parent.mkdir(exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    # Several containers can start at once on the same config volume. Linking
    # is atomic and fails when the target exists, so exactly one of them
    # writes the config and the others use it.
    try:
        os.link(tmp, target)
        print("Created config/__init__.py with a generated SECRET_KEY. "
              "Edit it to set MISP_WEBAPP_URL and MISP_WEBAPP_KEY.")
    except FileExistsError:
        pass
    finally:
        os.unlink(tmp)
PY

exec "$@"
