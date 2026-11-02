from datetime import date, datetime, timedelta, timezone
from itertools import groupby

from flask import Blueprint, render_template, request, url_for

import config
from webapp import audit

bp = Blueprint("logs", __name__)

# The newest entries shown at first, and added with each "Show older entries".
_PAGE = 200
_MOST = 2000
# The days the activity chart covers.
_CHART_DAYS = 90


def _day(raw: str) -> str:
    """A day to filter on, as YYYY-MM-DD, or "" for one that is no date."""
    try:
        return date.fromisoformat(raw).isoformat()
    except ValueError:
        return ""


def _long(day: date) -> str:
    return f"{day.strftime('%A')} {day.day} {day.strftime('%B %Y')}"


def _chart(dates: list, per_day: dict) -> dict:
    """The entries per day of ``dates``, and the busiest day, the latest of a
    tie, or None when there were none."""
    # The month is named under the first day and under each 1st.
    days = [{"date": d.isoformat(), "long": _long(d), "n": per_day.get(d.isoformat(), 0),
             "label": f"{d.day} {d.strftime('%b')}" if i == 0 or d.day == 1 else ""} for i, d in enumerate(dates)]
    busiest = max(reversed(days), key=lambda d: d["n"])
    return {"days": days, "busiest": busiest if busiest["n"] else None, "last_7d": sum(d["n"] for d in days[-7:])}


@bp.route("/logs")
def index():
    selected = {name: (request.args.get(name) or "").strip() for name in ("action", "type", "user")}
    day = _day((request.args.get("day") or "").strip())
    shown = min(_MOST, max(_PAGE, request.args.get("limit", _PAGE, type=int)))
    by = {"action": selected["action"] or None, "entity_type": selected["type"] or None,
          "user": selected["user"] or None}

    today = datetime.now(timezone.utc).date()
    dates = [today - timedelta(days=i) for i in range(_CHART_DAYS - 1, -1, -1)]
    found = audit.activity(dates[0].isoformat(), **by)
    chart = _chart(dates, found["per_day"])
    entries = [dict(e) for e in audit.get_logs(limit=shown + 1, day=day or None, **by)]
    older = len(entries) > shown
    # Under a heading per day, newest first, as the entries come.
    days = [{"date": d, "long": _long(date.fromisoformat(d)), "count": found["per_day"].get(d),
             "entries": list(rows)} for d, rows in groupby(entries[:shown], key=lambda e: e["timestamp"][:10])]
    filters = audit.log_filters()
    return render_template(
        "logs.html",
        days=days,
        shown=shown,
        older_url=(url_for("logs.index", **{**request.args.to_dict(), "limit": shown + _PAGE})
                   if older and shown < _MOST else ""),
        cut_off=older,
        found=found,
        chart=chart,
        chart_days=_CHART_DAYS,
        actions=filters["actions"],
        types=filters["types"],
        users=filters["users"],
        selected=selected,
        day=day,
        day_long=_long(date.fromisoformat(day)) if day else "",
        retention_days=getattr(config, "AUDIT_LOG_RETENTION_DAYS", 365),
    )
