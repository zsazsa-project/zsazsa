# Changelog

## 1.0.1

A set of fixes for the product pages, for the way records get their id, and for
MISP errors that zsazsa did not show. There is no migration to run.

### Upgrading

Pull and restart, that is all. The database gets a `sequence_counter` table on
the first start. The first time you save the Configuration page, six
`JOB_REDIS_*` settings are written to `config/__init__.py`. They hold the values
zsazsa was already using, so nothing changes for the background jobs.

One thing to know: record ids can have gaps now. A number for a PIR, GIR, RFI,
indicator feed, threat actor profile or landscape report is taken the moment it
is handed out, also when the MISP write after it fails. So you can see PIR-018
followed by PIR-020. In return, the same id is never given to two records.

### Fixed

- The Products page could not filter on product type. The dropdown used the name
  you see ("Flash intel alert") and the events carry the tag value
  ("flash-intel"), so every count showed 0 and picking a type gave an empty
  page. The two are now translated in both directions. Indicator feeds and
  threat actor profiles also get a link to their own page instead of to MISP.
- Two records created at the same moment could get the same id. The id came from
  a scan of the MISP event titles, so deleting a record gave its number back to
  the next one, and an id already sent to a stakeholder could come back on
  something else. Ids now come from a counter in the local database. The scan is
  still there, but only to set the starting point.
- Deleting a PIR, GIR, RFI, indicator feed, briefing, advisory, flash alert,
  landscape report or threat actor profile said "deleted" even when MISP refused
  it. The same for attributes and reports written during a create. The error
  from MISP now reaches the page. Deleting something that is already gone stays
  a success: that is the state you asked for.
- Lists stopped at the MISP page limit. With more than 200 stakeholders, PIRs or
  advisories you saw only the first page, and the id scan could start again from
  a number that was already used. All pages are read now.
- Fetching a URL in a manual entry gave a server error instead of a message when
  the address had an impossible port number, for example `:99999`.
- A newsletter with the old `TLP:WHITE` was stored as `white`. That is not a TLP
  level zsazsa knows, so the badge and the PDF stayed without colour. It is read
  as `TLP:CLEAR` now.
- The text export of an indicator feed repeated a value when it was found on
  more than one attribute, event or server. Each value is listed once now, in
  the order it was seen first. The CSV export does not change: it keeps one line
  per attribute, with the event and the server on it.
- The number of indicators above the result table did not apply the tag filters
  that the table itself applies, so the count and the table said something
  different as soon as you filtered on a tag.
- Saving the Configuration page put the Redis settings of the background jobs
  back to their default. Job state went to another Redis than before, without
  telling you.
- One unreadable row in the pipeline run log broke the whole pipeline page.
- Several requests at the same time each refreshed the PIR and GIR cache used
  for matching, and a save could still be lost when a refresh was busy.

### Changed

- The indicator count only asks MISP for the event context when you filter on a
  tag. That is the only case where it is needed.
- The distribution for new events takes the four levels the System tab offers.
  Another value in a hand-edited config falls back to "Your organisation only".

### Added

- `JOB_REDIS_*` in `config/__init__.py.example`, with the values zsazsa already
  used.
- Tests for the id allocation and the paging, for MISP errors that must not get
  lost, for the indicator count and export, for the product type mapping and for
  the URL check.

### Documentation

- INSTALL lists the system libraries WeasyPrint needs. `pip install -r
  requirements.txt` does not install them, and without them the PDF export only
  fails the first time somebody exports a product.
- INSTALL says which Redis settings you edit on the Settings page and which one
  you set in `config/__init__.py` itself.
- `docs/install.sh` checks `venv` and `ensurepip` before it creates the virtual
  environment and names the package to install. After the install it warns when
  WeasyPrint cannot be imported.
- The README explains what you get in the two export formats of an indicator
  feed.

### Internal

- The SSRF check for the URL fetch moved to `core/net_safety.py`. It is not used
  for MISP, Flowintel and the notification webhooks: an admin configures those
  and they are normally on an internal address.
- Reading a MISP attribute search, applying the tag filters locally and deleting
  an attribute that can already be gone are written once now, and used by the
  search, the export and the count.

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
