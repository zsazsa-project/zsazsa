# The zsazsa image, for the web app, the analyser and the IMAP collector.
FROM python:3.12-slim

# WeasyPrint renders every product PDF. It needs pango, harfbuzz-subset to
# embed fonts without a deprecation warning, and a font: the slim image has none.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
        fonts-dejavu-core shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# The import check fails the build when a native library is missing, rather
# than leaving PDF export broken until someone exports a product.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -c "import weasyprint, pymupdf"

RUN useradd --create-home --uid 1000 --user-group zsazsa

COPY --chown=zsazsa:zsazsa . .

# config/, data/ and zsazsaprompts/ are volumes. A volume hides what the image
# has at that path, so the shipped files are also kept under /opt/zsazsa, where
# the entrypoint copies any that are missing from on every start.
RUN mkdir -p /opt/zsazsa \
    && cp -a config data zsazsaprompts /opt/zsazsa/ \
    && chmod 0755 docker/entrypoint.sh

USER zsazsa

EXPOSE 5000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["python", "run_webapp.py"]
