# Changelog

## 1.0.5 - Under development

Newsletters from a mailbox were read as if they had been pasted out of a mail
client. The ETDA parser takes an edition in any of the shapes it arrives in now,
and a mail it finds nothing in says so.

### Upgrading

Pull and restart. Nothing to migrate and no setting to change.

Newsletters waiting for review are read again from the mail kept with them, so
they list their articles on the next visit. Ones already sent to the scraper
keep the names and tags they got. Deleting their event in MISP changes nothing.

Approving, publishing, resending and switching a stakeholder to automated
delivery now need the MISP publish permission (`perm_publish`) on the analyst's
role. With single sign-on configured, a request zsazsa cannot tie to a MISP user
is refused rather than let through. Check that the analysts who sign off on
products have a role with publish rights before upgrading.

`RULEZET_URL` is new and optional. Left empty, the Rulezet buttons are disabled
and a detection engineering request cannot be marked Active, since its rule
cannot be validated.

### Fixed

- A forwarded newsletter without a plain text part gave no articles at all. The
  review page said "0 of 0" while the mail itself was fine.
- Articles from the mailing list layout all landed in "Uncategorised", titled
  with their bullet or with the section name above them.
- A mail with no readable text was marked as collected and dropped. It is kept
  for review instead.
- Reading a mail marked it as read, even mail that was not for any source.
- A processed keyword the server refuses now goes to the log. Without it the
  same mail comes back on every run.
- An indicator feed with tag filters crashed. The AND/NOT query called PyMISP's
  build_complex_query on the class instead of on a connection.
- Pulling an event from a MISP server that had stopped answering held the page
  for as long as that server took, rather than the ten seconds the timeout
  promises. The thread pool was waiting for the stalled call on its way out.
- Single sign-on set up against the wrong Redis database was reported as
  "nothing is writing PHP sessions to this Redis". PHP takes the session database from
  `session.save_path` and MISP's installers leave that at 0, while MISP's own
  `redis_database` is 13 and easy to copy across. **Test single sign-on** now
  looks in the other databases of the same Redis and, when it finds the
  sessions there, names that database and the setting to change. The log says
  the same.

### Added

- Detection engineering request, a product for asking the detection engineering
  team for a new detection on a technique, actor or campaign. It is reviewed
  and approved like the other products, and then follows its own engineering
  status (Pending, In Dev, In Test, Active, Retired) on a board of its own. A
  request is only Active with a draft rule that passes Rulezet's validator, and
  the stakeholders hear about it the first time it gets there.
- Rulezet lookup. The vulnerability advisory, threat actor profile and daily
  briefing forms search a Rulezet instance for public detection rules by CVE ID
  or MITRE ATT&CK technique, show them with syntax highlighting, and add the
  ones picked to the detection rules of the product.
- A detection rules field on the daily briefing, shown on its page, in the
  e-mail and in the PDF.
- The review queue marks a newsletter with no articles in it, and the review
  page says so instead of showing an empty form.
- Newsletter e-mails as test fixtures, read both as they arrived and with their
  plain text part taken out.

### Changed

- A published flash intel alert or vulnerability advisory can no longer be
  edited by posting to its edit page. Only the button was hidden, and a resend
  then delivered the changed product under the original approval.

### Internal

- Linting moved from pyflakes to ruff, with the rule selection written out in
  `ruff.toml` so a local run reports the same as CI.
- Tests that every setting in `config/__init__.py.example` is explained in
  INSTALL.md, and that a CTI product with its own page is registered everywhere
  it has to be.
- Tests for the Rulezet lookup and its API routes, the detection engineering
  request object, status workflow and notifications, and the publish permission
  on every route that approves or sends a product.

## 1.0.4

An indicator feed asking MISP for two tags at once came back empty while
thousands of indicators matched. Along with that, several things around the
query that were wrong or unclear, and a count that said only "count failed".

### Upgrading

Pull and restart. Nothing to migrate and no setting to change. The MISP webapp store is  now also included in feeds, a cached feed shows after its next refresh.

### Fixed

- A feed with two or more included tags returned nothing while plenty matched.
  The query now uses PyMISP's `build_complex_query`.
- A feed that excludes the warninglist handed back fewer indicators than its
  limit asked for: MISP applies the limit and then drops the warninglisted
  values.
- The indicator count said "count failed" and nothing else. It now says which
  server failed and how, for example "MISP-Intern did not answer within 30s". A
  failed search says the same instead of "no MISP server answered".
- An organisation UUID pasted into the query is shown as the organisation it
  names.
- A MISP server configured without an API key was left out of the indicator
  feed's server list rather than shown as unusable, so enabling it looked like
  it had done nothing. It is listed now, greyed out and marked "No API key".

### Added

- zsazsa's own MISP is one of the servers an indicator feed can be built from.

### Changed

- An indicator that sits on more than one server is reported once, by the first
  server in the list that carries it.
- The tags and organisations pickers say what they mean: every tag on the plus
  row has to be there and none of the minus row, while organisations are any of
  them, which is the opposite reading of two controls that look identical.
- The results table is a little smaller, and to_ids sits next to the type rather
  than at the far end.

### Internal

- The indicator query is built from PyMISP arguments throughout, with no MISP
  REST parameter names mixed in.

## 1.0.3

PyMISP 2.5.34.2 stopped parsing the galaxy clusters a MISP server sends, which
left the MISP scraper collecting nothing and the galaxy pick-lists empty. zsazsa
works on that release now, and on the earlier ones as it did before.

### Upgrading

Pull and restart. Nothing to migrate and no setting to change. PyMISP is not
held below 2.5.34.2, so `pip install -r requirements.txt` moves you to it if you
are not there yet.

### Fixed

- PyMISP 2.5.34.2 refuses to parse a galaxy cluster that MISP flags as
  `default`, which is every cluster from its own galaxy library, because the
  server sends it carrying a distribution. The rule is meant for a cluster you
  build to send, but the same code parses what comes back, and a missing comma
  had kept it from ever firing until that release (MISP/PyMISP#1459). Nothing
  carrying a galaxy could be read: the MISP scraper source ended every refresh
  at zero events with "The field 'distribution' cannot be set on a default
  galaxy cluster" in the log, and the threat actor, sector, geography and ATT&CK
  pick-lists came up empty on every form. zsazsa drops those two fields before
  PyMISP sees them, and only on a release that refuses them, so an older PyMISP
  and a fixed one to come are both left alone. Reported in issue #22.

### Internal

- `core/pymisp_compat.py` decides what to do by asking the installed PyMISP to
  parse a cluster in the shape a server sends, rather than by comparing version
  numbers, so it stops patching of its own accord once PyMISP accepts them
  again. Tested against 2.5.8, 2.5.17.3, 2.5.32, 2.5.34.1 and 2.5.34.2.

## 1.0.2

A security fix, a set of smaller ones, and the indicator feed reworked into a
product with its own list and page. Upgrade for the first item: text that comes
in from articles, newsletters and the model was put in the page as HTML.

### Upgrading

Pull and restart. Nothing to migrate and no setting to change. A cached feed
writes its files under `data/feed_cache`, which zsazsa creates itself.

### Fixed

- Text from an article, a newsletter or the model was put in the page as HTML,
  so a `<script>` or an `onerror` in a summary, a write-up or a briefing story
  ran in the browser of the analyst who opened the page. It is shown as text
  now. Markdown keeps working: bold, links, code, lists, tables and line breaks.
- A download link of an indicator feed with an extension that does not exist
  returned the CSV anyway, instead of saying the page is not there.
- The public URL of a feed built its query in a slightly different way than the
  feed page, so the two could show different indicators. Both start from the
  same defaults now.
- When MISP could not be reached, the manual collection sources disappeared from
  the source list without a line in the log, as if somebody had deleted them.
- A threat actor profile embedded only as many indicators of a linked feed as
  the feed itself lists. A feed of 100 while the query matched 500 handed the
  stakeholder 100 indicators as if that were all of them. The product now says
  when a feed reached its limit, and says so as well when a feed could not be
  read at all rather than printing it as a feed with nothing in it.
- Deleting an indicator feed that a threat actor profile links to said nothing,
  while the profile loses it quietly. The confirmation now names the profiles.
- The products page counted the event reports of every product. An indicator
  feed keeps a query and no report, so the column said 0 for each of them and
  finding that out cost a MISP call per feed. The column is left out there.
- An indicator search where no MISP server answered looked like a query that
  matches nothing: the page said no indicators match, and a cached feed wrote
  that empty answer to disk and kept serving it. zsazsa now says the search
  failed, and a cached feed hands out the copy it already has instead of an
  empty answer, which whatever pulls the URL cannot tell apart from a feed that
  was emptied on purpose.

### Added

- `truncate=off` on the download links and on the public URL of a feed. The
  limit of the query sizes the result table and the exports followed it, so a
  feed with limit 100 handed out 100 indicators while the query matched far
  more. With `truncate=off` you get everything that matches, up to 10000.
- Two more formats for a feed. "Type + value" is the value list with
  the type in front, separated by a tab because values do carry commas. "JSON"
  is one document with the feed, its TLP, the moment the query ran and every
  indicator with its event, server and tags. Both are download buttons and
  `format=tsv` / `format=json` on the feed URL. The value list and the CSV do
  not change.
- Caching for a feed, off by default: switch it on when you save and pick
  hourly, daily or weekly. The first request writes all four formats under
  `data/feed_cache` and the next ones read those, which takes a pull from over a
  second to a millisecond. The schedule follows the moment you saved, so feeds
  do not all come due at once, and the analyser run re-runs the ones that are
  due. Saving drops the cache, a query that failed is never cached, and the
  results table on the page keeps querying MISP. A refresh that does not work
  leaves the feed serving what it has and says so, on the feed page and in the
  Caching column of the list, and every refresh the analyser does is in the log
  under `/logs`. Files of feeds that no longer exist are dropped there too.
- The indicator feed is a product list and a product page now, like the
  briefings and the flash alerts. The list is one row per feed with its actions;
  the page holds the product fields, the recipients, the threat actor profiles
  that embed the feed, the PyMISP query, the query in one line with the builder
  folded behind it, and the indicators. **New feed**, at
  `/products/indicator-feed/new`, opens that same page with every field empty,
  so building a feed and editing one are one form and not two. **Run search**
  replaces only the list of indicators, without reloading the page. A link kept
  from the old query page still opens the builder with its filters.

### Internal

- `requirements.txt` names `werkzeug` and `markupsafe`, which the code imports
  itself and until now only got because Flask brings them along.
  `flask-sqlalchemy` is removed, nothing in zsazsa imports it.
- Tests for the feed downloads and the public URL, the cache schedule, the two
  feed pages and the HTML escaping in the Markdown fields.

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
- The indicator CSV was written twice, once for the downloads and once for the
  profile embed. There is one writer now. The default limit of 100 is one constant now.

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
