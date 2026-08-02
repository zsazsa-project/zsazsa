"""Brand identity (company, colours, logo) shared by PDF and e-mail rendering.

Products go out as a PDF and as an HTML e-mail, and both need the same header
identity, so the values are resolved here once instead of per route.
"""

import base64
import mimetypes
from pathlib import Path

import config

_UPLOADS_DIR = Path(__file__).parent.parent / "data" / "uploads"
_PDF_CSS = Path(__file__).parent / "static" / "css" / "product_pdf.css"


def pdf_css_url() -> str:
    """file:// URL of the shared product PDF stylesheet, for WeasyPrint."""
    return _PDF_CSS.resolve().as_uri()


def _logo_path():
    """Path to the configured brand logo, or None when it is unset or missing."""
    logo = getattr(config, "BRAND_LOGO", "")
    if not logo:
        return None
    path = _UPLOADS_DIR / logo
    return path if path.is_file() else None


def logo_data_uri() -> str:
    """Return the brand logo as a data: URI, or "" when no usable logo is set.

    A data URI keeps the logo self-contained, which WeasyPrint needs since it
    cannot fetch a relative static file.
    """
    path = _logo_path()
    if path is None:
        return ""
    mime = mimetypes.guess_type(str(path))[0] or "image/png"
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"


def logo_bytes() -> tuple | None:
    """Return (bytes, maintype, subtype) for the brand logo, or None.

    E-mail clients (Gmail in particular) refuse data: URIs in <img>, so the HTML
    mail references the logo as a related part instead of embedding it.
    """
    path = _logo_path()
    if path is None:
        return None
    mime = mimetypes.guess_type(str(path))[0] or "image/png"
    maintype, _, subtype = mime.partition("/")
    return path.read_bytes(), maintype or "image", subtype or "png"


def brand() -> dict:
    """Brand context for the PDF templates."""
    return {
        "company": getattr(config, "BRAND_COMPANY", ""),
        "department": getattr(config, "BRAND_DEPARTMENT", ""),
        "color1": getattr(config, "BRAND_COLOR_1", "#0f2d52"),
        "color2": getattr(config, "BRAND_COLOR_2", "#0078f1"),
        "color3": getattr(config, "BRAND_COLOR_3", "#64748b"),
        "logo_uri": logo_data_uri(),
    }
