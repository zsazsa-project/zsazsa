import hmac
import logging
import logging.handlers
import os
import secrets
from pathlib import Path

from flask import Flask, abort, g, redirect, request, session, jsonify, render_template
from markupsafe import Markup
from pymisp.exceptions import PyMISPError
from requests.exceptions import RequestException
from werkzeug.middleware.proxy_fix import ProxyFix

import config
from webapp import audit, misp_session, org_store, sso_users, collection_cache, indicator_meta_store
from webapp.utils import md_to_html, md_to_html_inline
from webapp.version import APP_VERSION


logger = logging.getLogger(__name__)


def _setup_file_logging():
    log_file = getattr(config, "LOG_FILE", "data/analyser.log")
    log_level = getattr(logging, getattr(config, "LOG_LEVEL", "INFO"), logging.INFO)
    Path(log_file).parent.mkdir(exist_ok=True)
    root = logging.getLogger()
    if not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        fmt = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=3
        )
        handler.setFormatter(fmt)
        root.setLevel(log_level)
        root.addHandler(handler)
    # Werkzeug logs every HTTP request at INFO; keep those out of the analyser log.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def create_app():
    app = Flask(__name__)

    secret_key = os.environ.get("SECRET_KEY") or getattr(config, "SECRET_KEY", None)
    if not secret_key:
        raise RuntimeError("SECRET_KEY is not configured")
    app.config["SECRET_KEY"] = secret_key
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    _setup_file_logging()
    audit.init()
    org_store.init_db()
    sso_users.init_db()
    indicator_meta_store.init_db()
    from core.db import init_db as _init_core_db
    _init_core_db()
    collection_cache.start_worker()

    def _csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)
        return session["_csrf_token"]

    @app.before_request
    def _validate_csrf():
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            expected = session.get("_csrf_token")
            if not token or not expected or not hmac.compare_digest(token, expected):
                abort(403)

    # Endpoints reachable without a MISP login (capability-URL / public APIs).
    _PUBLIC_ENDPOINTS = {"static", "indicator_feed.public_feed",
                         "threat_actor_profile.diamond_png"}

    @app.before_request
    def _load_misp_user():
        if request.endpoint in _PUBLIC_ENDPOINTS:
            return
        misp_session.load_request_user()
        if g.misp_user:
            sso_users.record_sighting(g.misp_user)
        login_url = misp_session.login_redirect_url()
        if login_url:
            return redirect(login_url)

    app.jinja_env.globals["csrf_token"] = _csrf_token

    app.jinja_env.globals["app_version"] = APP_VERSION

    @app.context_processor
    def _inject_globals():
        return {
            "misp_webapp_url": config.MISP_WEBAPP_URL,
            "brand_company": getattr(config, "BRAND_COMPANY", ""),
            "ui_theme": getattr(config, "THEME", "overmind"),
            "current_user_email": misp_session.current_user_email(),
        }

    @app.template_filter("md_inline")
    def _md_inline(s):
        """Render a short text field as inline Markdown (links, bold, line breaks)
        without a wrapping block element, for values shown inside a sentence,
        table cell or list item."""
        return Markup(md_to_html_inline(s))

    @app.template_filter("md")
    def _md(s):
        """Render a multi-paragraph text field as block Markdown (used in PDFs and
        other server-rendered output where client-side Markdown is unavailable)."""
        return Markup(md_to_html(s)) if s else ""

    @app.template_filter("slug")
    def _slug(s):
        if not s:
            return ""
        return (
            s.lower()
            .replace("'", "")
            .replace("+", "-")
            .replace(":", "")
            .replace(" ", "-")
        )

    @app.template_filter("mitre")
    def _mitre(s):
        """Expand a bare ATT&CK technique id to "T1566 - Phishing"."""
        # Imported here: misp_store imports back from this package, so it cannot
        # be pulled in while this module is still executing.
        from webapp.misp_store import mitre_technique_label

        return mitre_technique_label(s)

    @app.template_filter("scope_rows")
    def _scope_rows(story):
        """A briefing story's (label, values) scope pairs, as the e-mail shows them."""
        from webapp.misp_store import briefing_story_scope_rows

        return briefing_story_scope_rows(story)

    from webapp.routes.dashboard import bp as dashboard_bp
    from webapp.routes.stakeholders import bp as stakeholders_bp
    from webapp.routes.requirements import bp as requirements_bp
    from webapp.routes.stats import bp as stats_bp
    from webapp.routes.export import bp as export_bp
    from webapp.routes.logs import bp as logs_bp
    from webapp.routes.config_page import bp as config_page_bp
    from webapp.routes.data_collection import bp as data_collection_bp
    from webapp.routes.rfi import bp as rfi_bp
    from webapp.routes.products import bp as products_bp
    from webapp.routes.indicator_feed import bp as indicator_feed_bp
    from webapp.routes.threat_actor_profile import bp as threat_actor_profile_bp
    from webapp.routes.flash_intel import bp as flash_intel_bp
    from webapp.routes.community import bp as community_bp
    from webapp.routes.vea import bp as vea_bp
    from webapp.routes.daily_briefing import bp as daily_briefing_bp
    from webapp.routes.threat_landscape import bp as threat_landscape_bp
    from webapp.routes.api import bp as api_bp
    from webapp.routes.collection_sources import bp as collection_sources_bp
    from webapp.routes.pipeline import bp as pipeline_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(stakeholders_bp, url_prefix="/stakeholders")
    app.register_blueprint(requirements_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(export_bp, url_prefix="/export")
    app.register_blueprint(logs_bp)
    app.register_blueprint(config_page_bp)
    app.register_blueprint(data_collection_bp)
    app.register_blueprint(rfi_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(indicator_feed_bp)
    app.register_blueprint(threat_actor_profile_bp)
    app.register_blueprint(flash_intel_bp)
    app.register_blueprint(vea_bp)
    app.register_blueprint(daily_briefing_bp)
    app.register_blueprint(threat_landscape_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(community_bp)
    app.register_blueprint(collection_sources_bp)
    app.register_blueprint(pipeline_bp)

    def _wants_json() -> bool:
        if request.path.startswith("/api/"):
            return True
        best = request.accept_mimetypes.best
        if best == "application/json" and (
            request.accept_mimetypes["application/json"]
            >= request.accept_mimetypes["text/html"]
        ):
            return True
        return False

    def _record_misp_error(exc: Exception) -> None:
        details = (
            f"path={request.path}; method={request.method}; "
            f"endpoint={request.endpoint or ''}; error={str(exc)[:900]}"
        )
        try:
            audit.record("error", "misp_connection", details=details)
        except Exception:
            logger.exception("Failed to write misp_connection error to audit log")

    @app.errorhandler(PyMISPError)
    def _handle_pymisp_error(exc):
        logger.warning("MISP connection error on %s: %s", request.path, exc)
        _record_misp_error(exc)
        if _wants_json():
            return jsonify({
                "ok": False,
                "error": "The MISP web app store is currently unreachable. This service is crucial for a functional application. Please retry shortly or verify the MISP web app configuration.",
            }), 503
        return render_template(
            "errors/service_unavailable.html",
            title="MISP web app store unavailable",
            message="The MISP web app store is currently unreachable. It is crucial for a functional application. Please retry shortly or check the MISP web app configuration.",
        ), 503

    @app.errorhandler(RequestException)
    def _handle_request_error(exc):
        logger.warning("Upstream request error on %s: %s", request.path, exc)
        _record_misp_error(exc)
        if _wants_json():
            return jsonify({
                "ok": False,
                "error": "Upstream service is currently unreachable. Please retry shortly.",
            }), 503
        return render_template(
            "errors/service_unavailable.html",
            title="Service unavailable",
            message="An upstream service is currently unreachable. Please retry shortly.",
        ), 503

    # Trust X-Forwarded-For/Proto/Host/Prefix from one upstream proxy (Apache).
    # When run directly without a proxy, none of these headers arrive and
    # request.script_root remains '', so direct access is unaffected.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    return app
