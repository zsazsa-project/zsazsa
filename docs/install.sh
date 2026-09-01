#!/usr/bin/env bash
# install.sh - set up zsazsa for the first time
#
# What this script does:
#   1. Checks for Python 3.10+ and pip
#   2. Creates a Python virtual environment in ./venv
#   3. Installs all dependencies from requirements.txt
#   4. Creates the data/ directory
#   5. Creates config/__init__.py from config/__init__.py.example (if not present)
#   6. Optionally generates a self-signed SSL certificate
#
# Usage (run from the project root, not from docs/):
#   bash docs/install.sh
#
# After running:
#   1. Edit config/__init__.py and fill in your MISP_URL, MISP_KEY, etc.
#   2. Start the application: source venv/bin/activate && python run_webapp.py
#   3. (Optional) install as a service: see docs/zsazsa.service.template

set -euo pipefail

PYTHON="${PYTHON:-python3}"
VENV_DIR="venv"
CONFIG_FILE="config/__init__.py"
CONFIG_EXAMPLE="config/__init__.py.example"
DATA_DIR="data"

echo "============================================================"
echo " zsazsa installer"
echo "============================================================"
echo ""
echo "This installer uses ./venv as the project virtual environment."
echo ""

# ── 1. Python version check ────────────────────────────────────────────────────

if ! command -v "$PYTHON" &>/dev/null; then
    echo "ERROR: Python 3 not found. Install Python 3.10 or later and re-run."
    exit 1
fi

PYTHON_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")

if [[ "$PYTHON_MAJOR" -lt 3 ]] || { [[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -lt 10 ]]; }; then
    echo "ERROR: Python 3.10 or later is required (found $PYTHON_VERSION)."
    exit 1
fi

echo "Python $PYTHON_VERSION found."

# The venv module ships separately from python3 on Debian/Ubuntu (e.g. the
# python3.12-venv package). Check it here so the failure is a clear one-line
# message naming the exact package, rather than a raw traceback part-way
# through creating the virtual environment below.
if ! "$PYTHON" -c "import venv, ensurepip" &>/dev/null; then
    echo "ERROR: the 'venv'/'ensurepip' module is not available for $PYTHON."
    echo "  On Debian/Ubuntu, install it with:"
    echo "    sudo apt-get install python3.${PYTHON_MINOR}-venv"
    echo "  Then re-run this installer."
    exit 1
fi

# ── 2. Create virtual environment ─────────────────────────────────────────────

if [[ -d "$VENV_DIR" ]]; then
    echo "Virtual environment already exists at ./$VENV_DIR - skipping creation."
else
    echo "Creating virtual environment in ./$VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

PIP="$VENV_DIR/bin/pip"

# ── 3. Install dependencies ───────────────────────────────────────────────────

echo "Installing dependencies from requirements.txt ..."
"$PIP" install --upgrade pip --quiet
"$PIP" install -r requirements.txt --quiet
echo "Dependencies installed."

# WeasyPrint (PDF export for every CTI product) needs native libraries that
# pip cannot install (cairo, pango, gdk-pixbuf). Warn now, without failing the
# install, so the gap is caught here and not the first time someone exports a
# product.
if ! "$VENV_DIR/bin/python" -c "import weasyprint" &>/dev/null; then
    echo ""
    echo "WARNING: WeasyPrint could not be imported - PDF export will not work"
    echo "  until the required system libraries are installed. See the"
    echo "  'System packages' section of INSTALL.md, or:"
    echo "    sudo apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \\"
    echo "        libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info"
    echo ""
fi

# ── 4. Create data directory ──────────────────────────────────────────────────

if [[ ! -d "$DATA_DIR" ]]; then
    mkdir -p "$DATA_DIR"
    echo "Created $DATA_DIR/ directory."
fi

# ── 5. Create initial config/__init__.py ──────────────────────────────────────

mkdir -p config

if [[ -f "$CONFIG_FILE" ]]; then
    echo "config/__init__.py already exists - skipping."
elif [[ ! -f "$CONFIG_EXAMPLE" ]]; then
    echo "ERROR: $CONFIG_EXAMPLE is missing, cannot create $CONFIG_FILE."
    exit 1
else
    # The example is the template for a fresh config. Copy it with a secret of its
    # own, generated in the same step so it never appears on a command line.
    "$VENV_DIR/bin/python" - "$CONFIG_EXAMPLE" "$CONFIG_FILE" <<'PY'
import pathlib, re, secrets, sys

example, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
key = f"SECRET_KEY = {secrets.token_hex(32)!r}"
text, count = re.subn(r"^SECRET_KEY = .*", key, example.read_text(), count=1, flags=re.M)
if not count:
    sys.exit(f"{example} has no SECRET_KEY line to replace")
target.write_text(text)
PY

    echo "Created config/__init__.py from config/__init__.py.example with a generated SECRET_KEY."
    echo ""
    echo "  >>> ACTION REQUIRED: edit config/__init__.py and fill in MISP_URL, MISP_KEY,"
    echo "      MISP_WEBAPP_URL and MISP_WEBAPP_KEY before starting the application."
    echo "      Everything else, including the LLM key, can be set from the web interface."
    echo ""
fi

# ── 6. Optional: SSL certificate ──────────────────────────────────────────────

echo ""
echo "A self-signed certificate is only needed when the built-in web server serves"
echo "HTTPS itself. Behind an Apache reverse proxy, Apache terminates TLS instead."
read -r -p "Generate a self-signed SSL certificate? [y/N] " ssl_answer
if [[ "${ssl_answer,,}" == "y" ]]; then
    read -r -p "Hostname for the certificate [this host]: " ssl_hostname
    if command -v openssl &>/dev/null; then
        bash docs/create_cert.sh "$ssl_hostname"
    else
        echo "WARNING: openssl not found - skipping certificate generation."
        echo "  Install openssl and run:  bash docs/create_cert.sh"
    fi
else
    echo "Skipping SSL certificate generation."
fi

# ── Done ───────────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo " Installation complete"
echo "============================================================"
echo ""
echo "To start zsazsa:"
echo "  source $VENV_DIR/bin/activate"
echo "  python run_webapp.py"
echo ""
echo "Or with the venv path explicit (no activation needed):"
echo "  $VENV_DIR/bin/python run_webapp.py"
echo ""
echo "To install as a systemd service, see: docs/zsazsa.service.template"
echo ""
