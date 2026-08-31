# Changelog

## 1.0.0

First release labelled as stable. It carries three fixes for data that was being
lost silently, so read the upgrade note before installing it.

### Upgrading

After pulling and restarting, open **Configuration > System** and run
**Align requirement scope and scope items**. It is a dry-run first and safe to
run twice. Before this release a technology, vendor, incident or campaign was
written to only one of the two places a requirement keeps its scope, so it was
either invisible on the detail page or matched nothing; the migration fills in
whichever side is missing.

If any of your RFIs show no `RFI-xxx` id, also run **Restore lost RFI ids**.
Saving feedback on an RFI used to take the id off it and out of the event title,
but MISP keeps the attribute it soft-deleted, so the id can be read back and put
in place.

One thing cannot be repaired. A PIR whose status was changed has lost its scope
items; **Align requirement scope and scope items** rebuilds them from the
requirement's scope lists, but any notes typed against them are gone.

### Fixed

- Saving feedback on an RFI deleted its id, both the attribute and the id in the
  MISP event title, which also freed that number for the next RFI to reuse. The
  store now carries the id forward even when a caller forgets to send it.
- Changing a PIR's status deleted every scope item on it. The store now replaces
  scope items only when the caller sends them, so a status change or a Kanban
  move leaves them alone.
- Editing a PIR deleted the scope items the form has no field for, along with
  the notes typed against the ones it kept.
- Generating an AI summary from the data collection page applied no scope tags.
  It read the summary with a parser written for an older layout and silently
  found nothing; it now uses the same reader as the analyser and applies the
  same sector, geography, ATT&CK and threat actor tags.
- ATT&CK techniques in a requirement's scope matched no events, although the
  documentation listed them as a scope element.
- The IT-ISAC newsletter importer published the newsletter's own link instead of
  the article's when an edition carried one above the first article, and folded
  two articles into one when an edition arrived without a rule between them.
- The review screen showed an "Important" badge on newsletters that grade
  nothing, and claimed critical and urgent were pre-selected when nothing was.
- A PIR notification printed its consequences as a raw Python list.
- Creating or editing a threat actor profile answered with a stack trace when
  MISP was unreachable, rather than the form and a warning.
- Four tests for the single sign-on check had been failing since the SSO fix
  landed; they connected to whatever Redis the developer had configured and
  reported that failure instead of the case under test.

### Changed

- A scope item is now the same thing wherever it is typed. All eight categories
  the detail page offers are written to both the requirement and its scope
  items, so each one shows on the page, is matched against events and reaches
  the notification. This changes matching results on existing data: requirements
  will flag events they did not flag before.
- The scope preview searches every scope dimension instead of four.
- Technology, vendor, incident and campaign are shown on the GIR detail page.
- The daily briefing seeds at most eight stories from one selection, as before,
  but now says so instead of silently dropping the rest.
- Downloaded indicator feed filenames are derived safely from the feed name.
- Failures that were swallowed silently are now logged: a briefing that will not
  save, a scope tag lost on a manual entry, an unreachable MISP behind an empty
  newsletter review queue.

### Added

- `scripts/align_requirement_scope_focus_points.py` and
  `scripts/restore_rfi_ids.py`, both listed under Configuration > System.
- `pillow` as a declared dependency. The Diamond Model renderer imports it
  directly and until now only received it through weasyprint.
- Continuous integration running the test suite on every push.

### Documentation

- INSTALL says which server zsazsa runs on and why it has to stay one process,
  that its listener is reachable on every interface unless you close the port,
  and that an upgrade may need a migration.
- The README no longer claims manual collection entries carry the scraper marker
  tag; they never did.

### Internal

- `datetime.utcnow()`, deprecated in Python 3.12, is gone. Every timestamp keeps
  the exact text it had.
- Dependencies carry the versions this release was tested against.
- The newsletter importer checks that the newsletter it is asked to archive is
  one it can parse.
