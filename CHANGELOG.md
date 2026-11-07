# Changelog

## 1.0.10 - development

### Added

- Daily briefings have a rejected state, an optional rejection reason and a bulk-delete action for rejected briefings. The reason is shown in Metadata.
- Flash intel and advisory list previews offer rejection with an optional reason and the existing QA check against source. Each overview can delete all rejected products after confirmation.
- Detection engineering requests can be approved from the status board's "Approve first" button. It opens an inline review in the table, and approval refreshes the board.
- Support for Microsoft Teams as a notification channel.
- The stakeholder form has an icon next to "Products subscribed" that subscribes the stakeholder to every product, or clears the list.
- AI settings for the AI-connector MISP module, with a "Test connection" button.
- The Configuration page warns when `MISP_WEBAPP_KEY` is read-only or its role lacks a permission zsazsa uses.
- MISP servers under Collection sources have an "Allow adding reports to events" switch. With it, data collection (or analyser) adds the AI summary on that server's events.
- The AI-connector MISP module can summarise events from such a server (robot icon).
- The dashboard shows how many products wait for a review or are drafts.
- On the manual entry form, the AI summary ticks the scope items it names. The form also has a MITRE ATT&CK picker.
- The scheduled analyser can also make vulnerability advisories and the daily briefing.
- The alert and advisory lists show under the title why the analyser made a draft: the requirement, focus points or CVE it matched.
- The lists of daily briefings, flash intel alerts, vulnerability advisories, indicator feeds, threat actor profiles and detection engineering requests have a "How ... is made" line under their filters. It opens each step from collection to delivery, and who does it: an analyst or the analyser.
- PIRs can link to active GIRs, with clickable relationships on detail pages and beneath list titles.
- The audit log under Reporting > Logs is pruned after `AUDIT_LOG_RETENTION_DAYS`, 365 by default. 0 keeps it for good, which the Logs page then says.
- On the flash intel and advisory lists, drafts and those waiting for review can be ticked, then approved and published, rejected or deleted together from the top of the table. The daily briefing list does the same for its drafts.
- Stories in a daily briefing can be ticked in its Contents list and deleted together with "Delete stories". Shift-click ticks a range.
- An analyst's `cti-evaluation` relevance score pushes an event to an alert (very high) or the briefing (high), or keeps it out of both (low or lower), whatever the AI says. Their other scores replace the model's.
- Settings has an Analyser tab with all the analyser's settings, in the order it works. The other tabs have the same layout with an overview and a menu of their sections. The asset database moved to Connections, Rulezet has its own switch, `RULEZET_ENABLED`, the product types are edited as a list, and the Styling tab previews a product's PDF.
- Under Settings > Analyser, the analyser can be kept off the scraper, the manual entries or the MISP communities. The articles sent from newsletters go with the scraper.
- The focus points have a vendors list, and the geographies, sectors, threat types and threat actors offer the names of their MISP galaxy, marking a name the galaxy does not have.
- "Start analyser" can read the last hours again, for after a change to the focus points, a requirement or a prompt.
- In the Pipeline activity, an event the analyser declined has a Push button, which sets the relevance score that pushes it to the briefing or to an alert, and a Review by hand button, which flags it for follow-up and opens it again on Data collection.

### Changed

- An indicator feed's results table says how many unique values its rows hold when that is fewer, which is what the plain text list at the feed URL returns.
- The analyser reads what changed on each source since its previous completed run, instead of yesterday's and today's events, and reads an event again only once it changed. A source that cannot be reached is read again by the next run. The collection cache is no longer refreshed first.
- The analyser also reads the events with a report on the additional MISP servers, through each server's filters and at most its "Max events" a run. Each server has an "Analyse its events" switch, off until an administrator turns it on, as the text of its events then goes to the AI features. What the analyser decides about those events is kept in zsazsa, not on the server.
- In the Pipeline activity, an event's title links to it in the MISP it was read from. Each outcome has an icon for the kind of reason, and what the analyser wrote is shown under it, in full on the "i". The table is denser.
- Improved pipeline page and audit log.
- Use filters per day in audit log and Pipeline.
- Each analyser run lists what it decided per event on the Pipeline page, the advisory runs too. A story the briefing drops as told before or as duplicate coverage is in the Pipeline activity, as one the alerts drop was.
- One analyser run goes at a time. The dashboard shows the run that is going and holds its Start buttons, and a scheduled run that finds one going skips its hour.
- The analyser no longer rejects an event flagged for follow-up, also when its article is missing.
- The title exclusions keep events out of the flash intel alerts as well as the daily briefing. They do not apply to vulnerability advisories.
- One AI call judges each event for the alerts and the briefing at once. It scores the article on `cti-evaluation` and reads its publication date: an alert needs an article at most three days old, a briefing story one at most a week. The verdict is reused until the focus points, the requirements, the prompt, the model or the article change.
- Focus points go to the AI with their type from the MISP galaxy they are in, and a threat actor with its synonyms.
- Settings > Analyser refuses a relevance score that pulls an event out as high as one that pushes it in.
- A vendor's vulnerability notice that reports no exploitation goes to the advisories only, not to an alert or the briefing.
- The alerts from focus points and from PIRs and GIRs are one option. An alert names every PIR and GIR in its grounds and is for all their stakeholders. A "Could have" PIR gives a briefing story but no alert, and a "Won't have" one is not considered. Alerts are drafted with the Build with AI prompt.
- The analyser no longer rejects an event as soon as one product turns it down. The daily briefing, or the alerts while the briefing is off, rejects the events every product declined, with the reasons in a report on the event.
- A story that an alert or briefing story of the last 30 days already tells, in any state, gets no second one. One that adds facts becomes an update naming the earlier product. A new AI feature, "Compare with earlier products", does the comparison, in place of the check against the open alerts.
- The daily briefing keeps at most 15 stories, the best first, and lists the rest under "Also seen" on the draft, from where an analyst adds one back. A later run on the same day adds to that day's draft.
- A CVE named by an advisory of the last 90 days gets no new one, unless it has since gone on the CISA KEV list or its CVSS score rose by 1.0 or more. A CVE also has to concern you: in the asset database, or a vendor or technology of the focus points or of an active PIR or GIR.
- The analyser also reads the manual collection entries that have a report, not counting a deleted one. It writes their AI summary and moves their workflow state on the webapp MISP they are kept on.
- Newer OpenAI models such as gpt-6-luna work: OpenAI calls use `max_completion_tokens`, and a temperature or `reasoning_effort` a model refuses is left out, instead of the request failing.
- A local model (on Ollama) no longer spends its token budget reasoning and returning an empty summary: zsazsa now turns thinking off with `reasoning_effort`, which Ollama's OpenAI endpoint reads, instead of `think`, which it ignores.
- The manual collection entry locks its summary while an AI summary is being written, and an event created before the summary is done gets it when it is, shows the Markdown preview as high as the editor in split view, and links to the Collection sources for a missing source.
- The PIR list hides rejected PIRs and the GIR list hides retired GIRs.
- The data collection table shows the ten words most titles share. A click on one searches for it.
- On the data collection page, the actions of an event wait while an AI summary is being written for it, and come back when the summary ends.
- While the analyser writes AI summaries for a daily briefing, flash intel alerts or advisories, the job says which one it is on.
- Daily briefings require threat information relevant to focus points or active PIRs/GIRs, or a major threat development. Keyword matches alone no longer qualify.
- Flash intel alerts are deduplicated against drafts, alerts in review and alerts created in the same run.
- Flash intel relevance checks exclude recaps, round-ups and keyword-only requirement matches.
- In Background jobs, Abandoned and All remove a stalled job that no worker is on, such as a run cut off by a restart. Before, it stayed listed for four hours.
- An RFI shows the answers given at triage in an Intake card, and they can be corrected on its edit form.
- The intake checklist of a PIR can be corrected on its edit form.
- With SSO, working in zsazsa keeps the MISP session alive: every five minutes, zsazsa requests MISP to refresh it.
- The Technology field on the PIR, GIR, threat actor profile and briefing story forms suggests "Firewall, Windows, Web servers" instead of product names.
- The SMTP server under Settings > Notifications has its own Save button, and refuses a host without a From address.
- A detection engineering request tags its source event when it is a manual entry too, as an alert and an advisory do.
- Webhook errors written to the log or shown by a channel test no longer include the `sig` parameter of a URL.
- The PIR and GIR distribution picker names a stakeholder's organisation instead of showing its UUID, and a GIR started from a stakeholder's page has that stakeholder as its owner and in its distribution, as a PIR already had.
- Scope items of a PIR and a GIR no longer have a note: the add form has no Notes field, notes are no longer shown or exported, and a scope item is stored as `category|value`.
- zsazsa needs Python 3.11 or later. Python 3.10 reached its end of life on 1 October 2026, and Pillow 13, which fixes the vulnerabilities below, no longer installs on it.
- An event gets at most one flash intel alert, whichever run made it.
- The flash intel alerts and vulnerability advisories the analyser drafts have an audience, so they can be published once reviewed. An alert from a PIR or GIR is for the requirement's owner and the stakeholders it is distributed to, any other draft for everyone who can receive it.
- Summary failures no longer stop analyser runs. Failed or unreadable briefing relevance checks leave events open but out of that briefing.
- Advisories are not duplicated for CVEs covered by drafts, advisories in review or rejected advisories.
- The relevance prompt tells the model that the publisher of an article is not a match. Unit 42 posts matched "Palo Alto".
- An analyser option whose search of the scraper MISP gets an error answer now fails and says why, instead of reporting no events.

### Fixed

- A feature on the AI tab whose settings were never saved went to OpenAI, whatever the default provider. It goes to the default provider now, as the AI tab says.
- A `cti-evaluation` score set on the data collection page left the earlier value of that score on the event. On another MISP server, which unpublishes an event that gets a tag, it also took the event off the page.
- A workflow state MISP refused left the event with none, and no analyser search found it again.
- A story deleted from a daily briefing came back in the next day's briefing, as its source event was left open. Saving the briefing now rejects that event.
- Saving a daily briefing deleted and wrote back every story report, this is slow. Only the reports that changed are written now.
- Unreadable AI relevance answers leave events open and are logged as errors. Relevance checks have a larger token budget.
- Focus-point alerts also filter by MISP event date, excluding recently edited old events. All analyser searches exclude future-dated events.
- The mail, MISP report and chat posts of a vulnerability advisory had an "Action required" line under the summary, filled with the most likely case from the risk assessment. Advisories have no such field, so the line is removed (issue #69).
- A failed MISP report request no longer rejects the source event as empty.
- Analyser products made from manual entries keep their webapp MISP source hint, so later edits and deletion update the right source event.
- An AI summary job from data collection that created nothing because every summary failed showed as done, in green, with only its message counting the errors. It now fails with the reason. One that created some summaries is shown in amber as done with errors.
- The scope preview of a PIR or GIR, and a PIR's Collection coverage card, counted events that had been rejected or dismissed in data collection. They are now left out.
- Changing a product's TLP left its MISP event with the old TLP tag, except on flash intel alerts, and threat actor profiles and indicator feeds had none at all. Saving a product now sets it.
- A PIR's Collection coverage card counted fewer events than its scope preview, because it left out the ATT&CK techniques. Both now search the same scope values.
- Bulk deletion checks the review state again on the event being deleted, so a product that is no longer rejected is not removed.
- A stale approval form cannot publish a rejected briefing. Inline briefing approval also asks for confirmation when its summary is out of date, as the detail page does.
- A PIR or GIR match from another MISP server or a manual source showed "Event not found" when opened from the scope preview or the PIR's recent matches. The link now names the source.
- The settings pages refused site admins when `MISP_WEBAPP_KEY` was not a site admin's key (#71). The role is now asked with the user's own session.
- With single sign-on, a short MISP `Session.timeout` or `Session.autoRegenerate` could end the session while working in zsazsa.
- Changing the review state of a vulnerability advisory deleted its summary, CVSS, CWE and context tags (#69). Its mail and MISP report now have the summary, CVSS and CWE.
- The service template reads `/etc/environment`, so an outbound proxy set there reaches zsazsa (#72). docker/README.md says how to give Docker the proxy.
- Saving the settings with single sign-on on and a `MISP_WEBAPP_KEY` without sync permission stored the session cookie name `MISP--`, after which zsazsa sent every request to MISP. The stored name is now kept.
- Updates to the follow-up flag. Flags lost when the cache was rebuilt come back, and a follow-up tag added or removed in MISP shows after the next refresh.
- The labelled lines of an AI summary ran together into one paragraph in MISP.
- AI summaries never tagged MITRE ATT&CK techniques, because zsazsa looked them up in the mitre-malware galaxy.
- Publishing a threat actor profile also publishes the underlying MISP event.
- A product type removed under Settings > Products still showed on the stakeholder list and pages.
- With a MISP key that has sync permission, the analyser took every event for a closed one, as MISP left out the local tags that hold the workflow state.
- A flash intel alert or vulnerability advisory whose object or report MISP refused was left behind as an empty event, which counted as the product of its source event.
- The MISP report of a new flash intel alert or vulnerability advisory had none of its content until the product was saved again.
- The analyser could file an alert from an AI answer with nothing in it, such as a refusal, and send it on automated mode.
- A failure to publish or deliver an alert on automated mode was not reported. It is logged on the event now.
- One vulnerability advisory MISP refused stopped the advisory run, on every run.
- The Pipeline activity hid the manual entries and the other MISP servers' events as orphaned, as it looked for every event on the scraper, and Purge orphaned deleted them. An entry from before the source was recorded now goes by the collection cache.
- Deleting an alert, advisory, detection request or briefing left the `zsazsa:product` tag on its source events, which then never got another advisory or briefing story. The tag is now delete unless another product of that type uses the event. The analyser reads the source events of a deleted alert, advisory or briefing again on its next run, unless the product was rejected. The delete confirmations say so: reject a draft to keep its story out.
- Saving a daily briefing at TLP:AMBER+STRICT or TLP:RED set it to TLP:CLEAR, as the form only offered clear, green and amber. It offers every level now.
- A story added to a daily briefing left its TLP as it was. The briefing now goes up to the TLP of the story's source event, and the form says so.

### Security

- Pillow is updated to 13.0.0 and certifi to 2026.10.19, for the advisories published against Pillow 12.3.0 and certifi 2026.7.22.
- brotli is updated to 1.2.1, and brotlicffi to 1.2.1.0, for the out-of-bounds write in the Brotli decoder (GHSA-9v8h-qqgm-4m35).

### Upgrading

- A feature on the AI tab you never saved now uses the default provider (Settings > AI). With a local default, check that the local model serves the features it now gets.
- The analyser reads an additional MISP server only once its "Analyse its events" is switched on under Collection sources. The text of its events then goes to the AI features, whatever their TLP, and to a cloud provider where the AI tab sets one. Each event costs a model call, and the first runs go through the server's whole "Events from last (days)" window, so check its filters first.
- The analyser keeps its watermarks, its lock and its decisions in four new tables, created when zsazsa starts. The first run of the alerts reads the last hour, and that of the briefing and the advisories the last day. `analyser_last_run` and `pipeline_last_action` in `data/state.json` are no longer read.
- `ANALYSER_FLASH_INTEL_REQUIREMENTS` and `POLL_WINDOW_HOURS` are gone, and saving Settings drops them. If only the alerts from PIRs and GIRs were on, switch on "Flash intel alerts" under Settings > Analyser.
- `analyser_relevance.md` and `analyser_major_development.md` replace the prompts `flash_intel_relevance.md` and `daily_briefing_relevance.md`. Make your changes to the old ones again on the Prompts tab, also with Docker. On the AI tab, "Judge article relevance" uses the settings of "Check article relevance" until it is saved, and "Review daily briefing relevance" is gone.
- `story_similarity.md` is a new prompt, for the comparison with earlier products. On the AI tab, "Compare with earlier products" starts with the default provider.
- `FOCUS_POINTS_VENDORS` is new and empty. Vendors listed under the technologies keep working there.
- The dashboard's Pending count no longer counts the scraper events that have a verdict but stay `incomplete` until the briefing closes them.
- Every event read after the update costs one model call for its verdict.
- The `zsazsa-daily-briefing` object template is now version 7 with an `also-seen` attribute. Nothing needs doing; existing briefings list nothing under "Also seen".
- The `zsazsa-flash-intel` object template is now version 6 with a `linked-requirement-uuids` attribute. Nothing needs doing: an existing alert reads as linked to its one PIR.
- Review the TLP of existing analyser products made from manual entries. New products respect the source classification; existing products are not rewritten.
- The next analyser run reads the manual entries that are still `incomplete` and have a report. One that no product wants is rejected, as a scraper event is. Set an entry to `complete` before updating to keep it out.
- Threat actor profiles and indicator feeds made before this release have no TLP tag on their MISP event, and a product other than a flash intel alert whose TLP was changed still has its old tag. Saving the product again sets the right one.
- The `zsazsa-pir` object template is now version 8 with a `linked-gir-uuids` attribute. Nothing needs doing; existing PIRs are linked to no GIR.
- The `zsazsa-daily-briefing` object template is now version 6 with a `rejection-reason` attribute. Nothing needs doing; existing briefings keep their state and have no rejection reason until rejected.
- zsazsa no longer runs on Python 3.10. `venv/bin/python --version` in the installation directory shows which one it uses. On 3.10, install Python 3.11 or later, move the old `venv` aside, create a new one as the web user with `python3.11 -m venv venv` (or the newer version you installed), and run `venv/bin/pip install -r requirements.txt` in it before restarting. The Docker installation runs its own Python 3.12 and needs nothing.
- Nothing needs doing for the scope item notes. A note already stored stays in MISP, unread, until the requirement's scope is saved again, which writes its items without one.
- Existing notification channels keep working, and the `NOTIFICATION_CHANNELS` format is unchanged apart from the new `teams` type.
- The `AI_CONNECTOR_*` settings are new and need nothing: the module stays disabled until set up on the AI tab.
- An advisory whose review state changed before this release lost its summary, CVSS, CWE and context tags. MISP keeps them as deleted attributes of its object: show the deleted attributes on the event in MISP and restore them.
- The collection cache gets two new columns. They are added when zsazsa starts, so nothing needs doing.
- The new `ANALYSER_*` settings need nothing. By default the scheduled analyser only makes flash intel alerts, as before.
- The first run after the upgrade removes audit log entries older than a year, and with them the delivery badge of products sent before then. The scheduled analyser runs on the new code without a restart, so to keep them, add `AUDIT_LOG_RETENTION_DAYS = 0`, or the number of days you want, to `config/__init__.py` before updating.
- The analyser's settings moved from the System tab to the Analyser tab, with their values. `ANALYSER_READ_SCRAPER`, `ANALYSER_READ_MANUAL` and `ANALYSER_READ_MISP_SERVERS` are new and on.
- `RULEZET_ENABLED` is new and on, so Rulezet stays as it was.
- The `event_log` table gets a `source_id` column, added when zsazsa starts. Older entries link to their event while it is in the collection cache.
- The `ASSET_INVENTORY_*` settings are new and need nothing: the asset database is off until switched on.
- The `zsazsa-flash-intel` (version 5) and `zsazsa-vea` (version 3) templates have a new `analyser-reason` attribute. Nothing needs doing; older drafts show no reason.
- The `zsazsa-vea` object template is now version 4 with a `cve-baselines` attribute. Nothing needs doing; for an existing advisory only its main CVE's change is measured.
- A rejected advisory keeps its CVEs out of new drafts for the 90 days of the coverage lookback. Delete it to allow another sooner.
- Threat actor profiles published before this release, and published products that got feedback, have an unpublished MISP event. Publish them in MISP if they should be.
- Source events of products deleted before this release keep their `zsazsa:product` tag. Remove it in MISP where it is in the way.
- `PIPELINE_RUN_LOG_RETENTION_DAYS` now defaults to 90 days. A value already saved under Settings stays as it is.
- Behind an outbound proxy, add `EnvironmentFile=-/etc/environment` to `/etc/systemd/system/zsazsa.service`, then `systemctl daemon-reload` and restart zsazsa.

## 1.0.9

### Added

- zsazsa runs in Docker, with the compose files in `docker/`.
  `bash docker/setup.sh` asks how MISP, its Redis and misp-scraper run on the
  host, writes `docker/.env` to match, then builds and starts the web app, the
  analyser, the IMAP collector and optionally misp-scraper. It works with MISP
  installed normally or in misp-docker, with or without single sign-on, and
  can add the `/zsazsa` proxy to MISP's Apache or to misp-core's nginx. The
  configuration, data and prompts stay in `docker/volumes/`. See
  docker/README.md. / via @chorsley and @elhoim
- A setup wizard, under Settings, takes a site admin through what a new
  zsazsa needs: the organisation and its logo, the data collection sources
  (MISP servers, mailboxes with their newsletters, manual sources), the AI
  providers, the focus points and the notification channels with the mail
  server. It saves to the same settings as the Settings page, can be run
  again at any time, and the dashboard points to it until zsazsa has sources
  and focus points.
- The web app listens on `ZSAZSA_BIND` and `ZSAZSA_PORT` when its environment
  sets them, so binding it to `127.0.0.1` no longer means editing
  `run_webapp.py`. The service template has the line.
- Indicator health on the pipeline page counts every enabled MISP server, cached and refreshable.

### Changed

- The documentation is reorganised. The quickstart moved to
  zsazsa-project.org and covers Docker and the standard installation, the
  setup wizard and a first briefing. INSTALL.md is about installing only, and
  the configuration reference moved from INSTALL.md to the "Configuration"
  section of the README, which now opens with links to both.
- A stakeholder who owns a PIR, GIR or RFI can no longer be deleted.
- PIR triage notices go only to the PIR's owner and distribution channels.
- Updated scope and statistics pages.
- The stakeholder list can be filtered by role and product subscription.
- PIRs can be filtered by priority and GIRs by review cycle. The RFI list leaves
  closed RFIs hidden by default.
- RFIs can be filtered by priority and SLA. The product lists have the same filters and charts.
- The daily briefing list can be filtered by state and TLP.
- A PIR or GIR is saved only with at least one intelligence level.

### Fixed

- HTTPS for the web app, single sign-on's login redirect and STARTTLS for the
  mail server could be switched on from the Settings page but not off again:
  an unticked switch sent nothing, so the stored value was kept.
- The logo upload took files of any size, although the Settings page says
  2 MB, and left no entry in the audit log.
- On a MISP without the `zsazsa-flash-intel` template, the analyser filed
  every flash intel draft without its object, and the log still said the draft
  was created. The object is now built from the template, and one MISP refuses
  is logged and noted in the activity log. The `osint:source-type` tag goes on
  the source event instead of its report, which MISP answered with Invalid
  Target.
- A threat landscape report could not be created on MISP before 2.5.40,
  which refused its object with "template_uuid: Please provide a valid RFC
  4122 UUID". The template had a version 7 UUID, which only newer MISP
  accepts; it now has a version 4 one, like the other templates. #64, reported
  by @angolion
- Saving a stakeholder that MISP could not load no longer creates a duplicate.
- Saving a PIR, GIR or RFI that MISP could not load no longer creates a duplicate.
- Approving or publishing a product that is already published no longer sends it twice.
- Publishing from a product's edit form now needs an audience, as Approve does.
- The PIR filter on All products found no product: it now reads each product's link.
- Statistics showed no products for the last 7 and 30 days and 0% PIR coverage.
- Flash intel alerts without their MISP object now show their title and id.
- A source with more events than its limit had its oldest cached, not its newest.
- Source health showed no event count or last event. It
  now shows the newest cached event.
- The "Max events" of a MISP server under Collection sources was saved but not used: the cache
  always read 500 events.
- The dashboard counted pending scraper events among the newest few hundred only.
- A stakeholder role or a product audience saved under an older spelling, such as "soc", now shows
  and filters correctly.
- The statistics page counted a PIR or GIR under its first intelligence level only.

### Security

- An indicator feed could disclose the public URLs of other feeds
  (GHSA-jw7f-22fc-mmvc). Feeds now
  leave out events tagged as a zsazsa record. The token is also kept to your
  organisation in MISP, so it no longer syncs to connected instances when
  `MISP_EVENT_DISTRIBUTION` shares events wider. A publisher can give a feed a
  new token.
  / reported by @elhoim
- The data collection page could change any event on zsazsa's own MISP.
- A threat actor profile sent its indicator feeds whatever their TLP.

### Upgrading

- The `zsazsa-threat-landscape-report` template has a new UUID. Nothing needs
  doing: zsazsa finds the object by name, so existing reports keep working,
  and a report's object takes the new UUID the next time it is saved.
- The collection cache has an `indicator_stats` table, created when the web app starts.
- The collection cache's `source_status` table has a new `last_limit_reached` column, added when the
  web app starts. Until a source's next refresh, it shows no limit warning.

## 1.0.8

Hardening contributed by @elhoim, and fixes found while reviewing the last
releases.

### Upgrading

Pull, run `pip install -r requirements.txt` as in the upgrade steps, and
restart. There is nothing to migrate.

`requirements.txt` now pins every package to an exact version, generated from
`requirements.in`, which has the ranges zsazsa needs.

In the CSV export of an indicator feed, a value that starts with `=`, `+`, `-`
or `@` now has a single quote in front.

### Added

- From this release on, each release on GitHub has a CycloneDX SBOM.

### Fixed

- A long number in the title of a MISP event could stop new PIRs, GIRs, RFIs,
  feeds, threat actor profiles and threat landscape reports from being created,
  or push their numbering up for good. Such a number is now skipped.
  / via @elhoim
- With the scraper switched off but still set to the same MISP as the web app,
  source events on that MISP were not found.
- A detection engineering request whose status change MISP refused showed an
  error page. The detail page and the board now say why.
- The daily briefing pages lost the AI drafting badge once the briefing had
  been delivered.
- The Rulezet lookup passed on anything that started with `CVE-`, so one value
  could hold several IDs separated by commas and get past the limit of ten. It
  and the CVE lookup now only take whole CVE IDs.
- A summary cut off at the model's token budget is now logged as a warning.
- On Python 3.10, pulling an event from a MISP server that had stopped
  answering was reported as a failed fetch rather than as a timeout.

### Security

- A product with a TLP level the clearance check could not read, such as
  `TLP:RED`, was treated as amber and reached stakeholders cleared for amber.
  An unreadable level now counts as red. / via @elhoim
- The example configuration shipped with MISP certificate checks off.
  / via @elhoim
- A value from MISP that looked like a spreadsheet formula ran as one when the
  CSV export, or the CSV of the exported PyMISP script, was opened in Excel or
  LibreOffice. / via @elhoim
- The installer wrote `config/__init__.py`, which holds the keys, readable by
  every user on the host. / via @elhoim

## 1.0.7

Threat landscape reports follow ENISA's method, from triaged events to a PDF.
The settings pages are for MISP site admins only and hide stored keys.
Seven reported security issues are fixed, and CDN files are pinned by hash.

### Upgrading

Pull and restart, there is nothing to migrate. A few things behave differently:

- Configuration and Collection sources need `perm_site_admin` on the MISP role.
  Other users no longer see the Settings menu. Installs without single sign-on
  are unchanged.
- Saved keys and passwords show as "Configured". Leave a field empty to keep
  it, use "Remove" to clear it.
- An indicator feed tracks if it has a public URL. Existing feeds
  keep their public URL, until someone with MISP publish rights switches it off. A new
  feed starts with it on only when a publisher creates it.
- zsazsa now only reads, changes or deletes an event when it has the
  zsazsa object or tag of the record type the page is about.

### Added

- A threat landscape report has a box for nation state, cybercrime,
  hacker-for-hire and hacktivist actors.
- Threat landscape reports follow ENISA's method. A report is built from
  events picked in a filtered queue.
- A threat landscape report downloads as a PDF with an annex on its dataset,
  and techniques as an ATT&CK Navigator layer.
- A feed's public URL can be switched on or off on the feed's page, by users
  with MISP publish rights only.
- The response of an RFI can be edited on the RFI's page.
- A vulnerability advisory is built with AI from its source events, the
  way a flash intel alert is done.

### Fixed

- An install whose configuration predates the detection engineering request,
  threat landscape report, threat actor profile or indicator feed no longer
  fails on that product's pages. A missing tag setting gets the default until
  the Settings page is saved.
- A page that cannot load marked or DOMPurify shows Markdown as plain text
  instead of nothing.

### Security

- Missing authorisation on the settings pages (GHSA-v6rj-fh3w-rx8x): any MISP
  user could read every stored credential and rewrite the configuration,
  including where single sign-on reads identities from, and so act as any user.
  / reported by @elhoim
- Diamond Model images of any threat actor profile, drafts included, were
  readable without a login (GHSA-x326-2rwv-jc78). / reported by @elhoim
- Delivering an indicator feed to stakeholders did not need the MISP publish
  right (GHSA-gp95-wrp9-v67f). / reported by @elhoim
- Any MISP user could delete or change MISP events that zsazsa did not
  create, by putting their id in the URL of a zsazsa page
  (GHSA-f8wh-26f3-4478). / reported by @elhoim
- A published daily briefing or threat landscape report could still be edited,
  also by users without MISP publish rights, and a resend then delivered the
  edited version (GHSA-rqcp-gv9j-jgv6). / reported by @elhoim
- A newsletter could make the scraper fetch internal addresses, a link
  fetched for a manual collection entry could reach an internal address
  through a DNS answer that changed after it was checked, and a failed MISP
  connection test showed the response of whatever host it reached
  (GHSA-24wh-h52p-fcgg). Newsletter links now have to be public web addresses,
  a fetched link connects to the address that was checked, connection tests
  answer with a fixed message, and organisation lookups use the server's TLS
  setting, defaulting to verification when it is not configured. / reported
  by @elhoim
- One mailed newsletter could stall the IMAP collector on every run, and the
  web app when the mail was opened for review, through patterns that
  backtracked over long runs of whitespace; so could a model answer with an
  unclosed code fence (GHSA-v4mq-r4g8-g35w). Parsing now takes time linear in
  the length of the text and reads every edition as before. / reported by
  @elhoim
- The scripts and stylesheets zsazsa loads from cdnjs are pinned by hash, so
  the browser refuses a file that was changed there.

## 1.0.6

AI drafting of the daily briefing now runs as a background job, and an
indicator feed can be exported as a standalone PyMISP script. PIR and RFI
triage is easier to follow and the stakeholder pages got some care. This
release also fixes two cross-site scripting issues, so upgrading is recommended.

### Upgrading

Pull and restart, there is nothing to migrate. A few things behave differently:

- Threat actor profile mails show the Diamond Model inline instead of attaching
  `diamond-model.png`.
- The organisation filter on an additional MISP server takes organisation UUIDs
  only.
- If your MISP URL ends in a slash, save the Settings page once to drop it.

### Added

- An indicator feed can be downloaded as a standalone PyMISP script.
- The stakeholder form has ready-made engagement strategies, products sorted
  with their icons, and Internal as the default type. On the matrix, hovering a
  name highlights that stakeholder.
- Organisations link to their page in MISP.
- Board cards for new PIRs and RFIs have a Triage button that opens the triage
  pane. An acknowledged or deferred PIR shows that on its button and in the pane.

### Fixed

- Briefing stories the model returned as a numbered list looked different from
  the others and lost their threat actor type.
- CVE IDs are checked before they go into the CIRCL lookup.
- Threat actor profiles sent by mail or Mattermost now include the full PDF.
- A briefing published while the AI was still drafting it now sends its
  notifications.
- The AI no longer leaves a profile's confidence blank while claiming to have
  filled it in.
- Markdown is no longer shown unsanitised when DOMPurify fails to load.
- Drafting a profile with AI keeps actors typed in while the MISP galaxy was
  unavailable.
- Links into MISP no longer get a double slash when the URL ends in one.

### Security

- Stored and DOM-based XSS (GHSA-2hmh-2qrq-872r): script in a MISP event
  title, an organisation name or a source or stakeholder name could run in the
  browser. / reported by @elhoim
- Stored and DOM-based XSS (GHSA-4rw2-wpj5-m23p): script in names and dates
  shown in confirmation dialogs, in the daily briefing editor and in MISP tags
  on the collection page could run in the browser. / reported by @elhoim

## 1.0.5

Newsletters from a mailbox were read as if they had been pasted out of a mail
client. The ETDA parser takes an edition in any of the shapes it arrives in now,
and a mail it finds nothing in says so. The misp-scraper has also become
optional: an installation that collects from other MISP servers can run without
one.

New intelligence product: **detection engineering request**. / via @ecrou-exact

Rulezet, the community detection-rule repository, is now part of the daily
threat briefing, the flash intel alert, the vulnerability advisory, the threat
actor profile and the detection engineering request. Rules are found by CVE or
by MITRE ATT&CK technique. / via @ecrou-exact

### Upgrading

Pull and restart. Nothing to migrate, and an installation with a scraper keeps
collecting exactly as it did. Two things do need attention first, both below:
the publish permission and the new product tag.

Approving, publishing, resending and switching a stakeholder to automated
delivery now need the MISP publish permission (`perm_publish`) on the analyst's
role. With single sign-on configured, a request zsazsa cannot tie to a MISP user
is refused rather than let through. Check that the analysts who sign off on
products have a **role with publish rights** before upgrading.

`TAG_DETECTION_ENG` is new and has no fallback in the code, so the detection
engineering request list fails until the key exists. Saving the configuration
once from Settings is enough to write it. To do it by hand instead, add this to
`config/__init__.py`:

    TAG_DETECTION_ENG = 'zsazsa:ctiproduct="detection-eng-request"'

`RULEZET_URL` is new and optional. Left empty, the Rulezet buttons are disabled
and a detection engineering request cannot be marked Active, since its rule
cannot be validated.

Newsletters waiting for review are read again from the mail kept with them, so
they list their articles on the next visit. Ones already sent to the scraper
keep the names and tags they got. Deleting their event in MISP changes nothing.

WeasyPrint must now be 70 or newer, which `pip install -r requirements.txt`
takes care of. Versions below it carry CVE-2026-55073, a server-side request
forgery in the renderer, and every product PDF goes through that renderer.

The flash intel alert object gained a `detection-rules` attribute, so its
template is at version 3. Nothing needs doing: the template is read from
zsazsa's own copy rather than from MISP, and an alert saved before this reads
back with no rules and gains them the next time it is edited.

To run without a scraper, turn **Enabled** off on its card under Collection
sources, or clear its URL and API key, and save. It leaves the Data collection
page, the requirement source lists and the dashboard, and its cached events go
on the next refresh. Nothing is removed from MISP, so switching it back on
restores it. A PIR or GIR naming `misp-scraper` loses that reference the next
time it is saved, as one naming a MISP server you disable already does.

Daily briefing stories now record which MISP server they came from. Ones saved
before this have none recorded and count as scraper events, which is what they
were.

### Fixed

- A threat actor profile went out to stakeholders without its
  recommendations, so any Rulezet rule attached to one never reached them.

- A flash intel alert was the only product whose notification carried no link
  back to it. Mattermost readers had the MISP event to fall back on, readers on
  mail had nothing, which matters now that an alert can carry detection rules.
  The alert stored on the event is unchanged.

- Events from a second MISP server could not be added to a daily briefing while
  the misp-scraper was unset or unreachable: its connection was built first and
  unguarded, so it took every other source down with it. The flash intel,
  advisory and landscape wizards were affected the same way.
  ([#29](https://github.com/zsazsa-project/zsazsa/issues/29))
- A daily briefing marked every story's source event on the scraper whatever
  server it came from, so events collected elsewhere were never marked.
- The PIR and GIR scope preview matched scraper events only, so it came back
  empty for an installation collecting from other MISP servers.
- Queuing an event for a threat landscape report, or flagging one for follow-up,
  used the scraper connection for manual entries, which live on the webapp MISP.
- An event on the webapp store, a manual entry among them, was never marked when
  used as a product source, so it could be drafted into a second product with
  nothing to show it had been covered.
- Events selected for a briefing that could not be read were dropped without a
  word. The count and the reason are shown now.
- The data collection page counted events that a filter had since hidden as
  still selected, so the badge could read "2 selected" with one row ticked, and
  a product built from the selection quietly included events that were not on
  screen. Selected now means ticked and visible; a tick on a hidden row comes
  back when the filter is cleared rather than being lost.
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

- The daily threat briefing, flash intel alert, vulnerability advisory,
  threat actor profile and detection engineering request show a view button
  beside each Rulezet link, which opens the rule in the viewer. Only its
  name and link are stored.
- The flash intel alert has a detection rules field, with the same Search
  Rulezet button as the other products.
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
- The misp-scraper is optional, with the same **Enabled** switch the other MISP
  servers have, so it can be turned off without losing its credentials. Without
  one, zsazsa runs on the other MISP servers and the manual sources alone.
  Newsletters still work, only pushing their article URLs needs a scraper.
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
