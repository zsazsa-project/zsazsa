# zsazsa container image: the web app, the analyser and the IMAP collector all
# run from it (see docker-compose.yml and the "Docker" section of INSTALL.md).
FROM python:3.12-slim

# Native libraries WeasyPrint needs to render the product PDFs, plus one font
# family: the slim image ships none, and a PDF without fonts renders blank.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
        fonts-dejavu-core shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home --uid 1000 --user-group zsazsa

COPY --chown=zsazsa:zsazsa . .

# Every state path is relative to /app. config/, data/ and zsazsaprompts/ are
# written at runtime and mounted as volumes, so they belong to the app user.
# The example config is also kept outside config/, where a volume cannot hide
# it, for the entrypoint to generate config/__init__.py from on first start.
RUN mkdir -p data config \
    && cp config/__init__.py.example docker/config.example.py \
    && chown -R zsazsa:zsazsa data config zsazsaprompts \
    && chmod 0755 docker/entrypoint.sh

USER zsazsa

EXPOSE 5000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["python", "run_webapp.py"]
