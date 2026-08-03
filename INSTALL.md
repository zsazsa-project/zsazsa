# Installing and configuring zsazsa

This guide covers everything needed to stand up zsazsa: the infrastructure it depends on, installation, configuration, running it, and deploying it. For what zsazsa does and how analysts use it, see [README.md](README.md).

## What you need before installing

zsazsa sits on top of MISP and requires the following infrastructure to be in place first:

- **A MISP server to store CTI program data.** This is where zsazsa saves its objects: stakeholders, PIRs, GIRs, flash intel alerts, advisories, briefings, and so on. This is the server you point `MISP_WEBAPP_URL` at.

- **A MISP server running misp-scraper.** The scraper feeds threat events into a MISP instance that zsazsa polls for the data collection view and the analyser pipeline. This is the server you point `MISP_URL` at. It can be the same server as above.

- **One or more additional MISP servers (optional but recommended).** zsazsa can pull threat events from other MISP instances configured under Collection sources. These act as supplementary intelligence feeds. Ideally they are separate servers from your own MISP, such as partner-operated or community instances.

zsazsa does not install MISP or misp-scraper. Follow the official installation guides for those projects first.

### Redis

zsazsa talks to Redis in three unrelated places, all optional and all configured separately. They can be the same server or three different ones.

| Use | Settings | Needed for |
|---|---|---|
| MISP's own session store | `MISP_SESSION_REDIS_*` | Single sign-on: reading the logged-in MISP user from MISP's session cookie |
| Background job state | `JOB_REDIS_*` | Sharing running-job state between browsers, tabs, processes and cron runs |
| The misp-scraper queue | `SCRAPER_REDIS_*` | Handing newsletter article URLs to the scraper for fetching |

zsazsa speaks Redis over a plain socket and does not need `redis-py`, so there is nothing extra to install on the zsazsa side. Without a job Redis the app keeps job state in process memory instead, and without the scraper Redis newsletter articles are archived but not pushed to the scraper. An unreachable session Redis is the one that bites: with single sign-on set to require a MISP session, no request can be identified and every one of them is bounced to MISP's login page, including the request that comes back from it. Leave `MISP_SESSION_REDIRECT_TO_LOGIN` off until you have confirmed zsazsa can read that Redis.

### System packages

Python 3.10 or later, with `venv` and `pip`. PDF export uses WeasyPrint, which renders through Pango rather than a bundled engine, so the system libraries have to be present: on Debian and Ubuntu that is `libpango-1.0-0` and `libpangoft2-1.0-0`. Without them everything works except PDF generation, which fails at the moment a product is exported.

## Installation

Installation is recommended inside the MISP custom application directory (create it if it does not already exist with `mkdir /var/www/MISP/misp-custom ; chown www-data:www-data /var/www/MISP/misp-custom`) so that it runs under the same web user as MISP. On Ubuntu this means installing as `www-data`:

```bash
cd /var/www/MISP/misp-custom
sudo -u www-data git clone <this-repo> zsazsa
cd zsazsa
sudo -u www-data bash docs/install.sh
```

The installer checks the Python version, creates a `venv` in the project root, installs the dependencies from `requirements.txt`, creates `data/`, and, when `config/__init__.py` does not exist yet, copies `config/__init__.py.example` into place and gives it a freshly generated `SECRET_KEY`. An existing config is left alone, so the script is safe to re-run. It finishes by offering to generate a self-signed TLS certificate; answer no unless you intend to serve zsazsa's built-in server directly over HTTPS. Behind Apache, TLS is terminated by Apache and the certificate is not used.

The certificate can also be created later, or renewed, on its own:

```bash
bash docs/create_cert.sh zsazsa.example.com
```

It writes `certs/zsazsa.crt` and `certs/zsazsa.key`, the paths `SSL_CERT` and `SSL_KEY` point at by default, and refuses to run if either already exists, so an existing key is never overwritten. Set `SSL_ENABLED = True` to use it. Leave the hostname off to use this host's own name.

### First configuration

`config/__init__.py.example` carries every setting the application reads, with neutral defaults, in the same layout the Settings page produces when it saves. Edit the copy the installer made and set at least `MISP_URL`, `MISP_KEY`, `MISP_WEBAPP_URL` and `MISP_WEBAPP_KEY`; everything else can wait for the interface. The LLM key, the notification channels, the collection sources and single sign-on all start empty or disabled, so the application comes up on nothing more than the two MISP connections.

If you want to run zsazsa as a systemd service, use `docs/zsazsa.service.template` as your starting point.

## Configuration

Main runtime settings are in `config/__init__.py`. You can configure:

- scraper and webapp MISP connections, and the distribution level of the events zsazsa creates
- optional extra MISP sources for the collection browser
- manual collection sources (a structured registry with name, owner, location, description, enable/disable, and an Admiralty scale reliability rating, each backed by a MISP event)
- IMAP mailboxes polled for forwarded newsletters
- the product type catalogue
- recommended immediate and near-term actions shown as presets in the Flash Intel and VEA wizards
- notification channels (named Mattermost webhooks, email recipients and Flowintel case management instances, each with a name and enable/disable toggle, plus the shared SMTP server used for email)
- single sign-on against MISP's session store
- the analyser polling window and marker tag
- log settings and file paths

The configuration page organises settings across tabs (Connections, Products, System, Prompts, AI, Context elements, Notifications and Styling). Collection sources, namely the MISP scraper connection, additional MISP servers, manual sources and IMAP mailboxes, are managed at `/config/sources/`. MISP connections can be tested live, each server entry can be saved individually, and manual sources have a per-source enable/disable with an in-use guard against PIR/GIR references. The config file is backed up automatically before each save. The full per-tab reference is in [Configuration settings](#configuration-settings) below.

## Running the application

```bash
source venv/bin/activate
python run_webapp.py
```

The application listens on `http://0.0.0.0:5000` by default, or on `https://` when `SSL_ENABLED` is on. Open it in a browser at the IP address or hostname of your server. The web process also runs the data collection cache worker, which refreshes events from every configured source in the background, so the Data collection page reads from `data/collection_cache.db` rather than querying MISP live.

Run the flash intel analyser pipeline, which turns new scraper events into flash intel drafts, typically from cron:

```bash
15 * * * * cd /var/www/MISP/misp-custom/zsazsa && venv/bin/python run_analyser.py
```

The daily briefing and vulnerability advisory pipelines are not part of this script. They are started from the dashboard, where they run as background jobs. Nothing any of them produce is published or sent to stakeholders: they only create drafts for review.

If you collect newsletters from a mailbox, poll it from cron as well (see "Collecting newsletters from a mailbox (IMAP)" in [README.md](README.md)):

```bash
*/15 * * * * cd /var/www/MISP/misp-custom/zsazsa && venv/bin/python run_imap_collector.py
```

Run both as the same user that owns the installation, since they write to the same database and log file as the web application.

The hostname zsazsa listens on, as well as the port, are configurable in `config/__init__.py`:

```python
HOSTNAME = 'zsazsa.example.com'   # or an IP address
PORT = 5000
```

These values can also be changed from the Settings page in the web app (System tab). After saving, restart the application for the port change to take effect (the `HOSTNAME` value is stored for reference; the listener address is always `0.0.0.0`).

## Production deployment behind Apache

zsazsa is designed to run alongside MISP and can be served under a subpath of the MISP Apache virtual host, for example `https://misp.example.com/zsazsa`. The application adapts to any subpath automatically, so `/cti`, `/cti-program`, or any other value works without changing the application.

Serving zsazsa under the MISP host is also what makes single sign-on possible: the browser only sends MISP's session cookie to zsazsa when both are on the same host.

### 1. Keep the app running with systemd

Copy the service template and adjust the paths and user:

```bash
sudo cp docs/zsazsa.service.template /etc/systemd/system/zsazsa.service
# edit the file, then:
sudo systemctl daemon-reload
sudo systemctl enable --now zsazsa.service
```

For production, bind the listener to localhost so it is only reachable through Apache. In `run_webapp.py`, change:

```python
app.run(host="0.0.0.0", ...)
```

to:

```python
app.run(host="127.0.0.1", ...)
```

Leave it as `0.0.0.0` for development if you need direct access from other machines on the network.

### 2. Enable the required Apache modules

```bash
sudo a2enmod proxy proxy_http headers
sudo systemctl reload apache2
```

### 3. Add the proxy to the MISP virtual host

Inside the existing `<VirtualHost *:443>` block in your MISP Apache configuration, add:

```apache
# zsazsa CTI application
ProxyPreserveHost On
RequestHeader set X-Forwarded-Prefix "/zsazsa"
RequestHeader set X-Forwarded-Proto "https"

ProxyPass        /zsazsa  http://127.0.0.1:5000/ timeout=300
ProxyPassReverse /zsazsa  http://127.0.0.1:5000/
```

The value in `RequestHeader set X-Forwarded-Prefix` must match the path used in `ProxyPass` and `ProxyPassReverse`. To use a different subpath, change all three occurrences. No application restart is needed for subpath changes, only an Apache reload (`systemctl reload apache2`).

The `timeout=300` is worth keeping. Apache's default proxy timeout follows `Timeout`, which is 60 seconds on a stock install, and the AI drafting buttons wait for the model in the request. A slow model, in particular a locally hosted one, otherwise returns a gateway timeout in the browser while the request is still running server-side. Long analyser runs, bulk AI summaries and product notifications are background jobs and are not affected.

The application reads `X-Forwarded-Prefix` at runtime to construct links and AJAX call paths, and reads `X-Forwarded-Proto` to build correct `https://` URLs in Mattermost notifications and product preview links. When run directly without a proxy, both headers are absent and the application behaves exactly as before.

## Upgrading

Go to the installation directory and pull as the web user:

```bash
cd /var/www/MISP/misp-custom/zsazsa
sudo -u www-data git pull
sudo -u www-data venv/bin/pip install -r requirements.txt
```

Then restart the service to pick up the changes:

```bash
sudo systemctl restart zsazsa.service
```

`config/__init__.py` is not in version control and survives the pull untouched. When an upgrade adds a setting, the value is defaulted until you save once from the Settings page, which rewrites the file in the new format. Upgrades that need existing MISP data rewritten expose that as a migration on the System tab, with a dry-run before anything is changed.

## Configuration settings

Almost all runtime settings are in `config/__init__.py`, and most of them can be changed from the web interface without editing the file directly. The main settings page is at `/config` and groups settings across eight tabs: **Connections**, **Products**, **System**, **Prompts**, **AI**, **Context elements**, **Notifications** and **Styling**. Collection sources, namely the MISP scraper connection, the list of additional **MISP servers**, the manual **collection sources** and the **IMAP mailboxes**, are managed on a separate page at `/config/sources/`, covered in [Creating data collection sources](#creating-data-collection-sources) below. Whichever page you save from, the previous version of `config/__init__.py` is copied to `config/__init__.py.backup` first, so only one generation of backup is kept.

Saving regenerates the whole file from a fixed template rather than editing lines in place. Anything you added by hand that the template does not know about is dropped on the next save. In practice this affects `JOB_REDIS_*` and `COLLECTION_CACHE_INTERVAL`, described under [Background jobs](#background-jobs) and [Settings not exposed in the interface](#settings-not-exposed-in-the-interface).

### Connections

This tab covers the MISP server zsazsa uses as its own **data store**, configured through `MISP_WEBAPP_URL`, `MISP_WEBAPP_KEY` and `MISP_WEBAPP_VERIFYCERT`. This is the MISP instance holding the stakeholder, PIR, GIR, RFI and product events created by zsazsa itself, and is separate from the scraper MISP described under data collection sources. The LLM credentials used to live here as well; they are now on the AI tab.

| Setting | Description |
|---|---|
| `MISP_WEBAPP_URL` | URL of the MISP server zsazsa uses to store its own program data |
| `MISP_WEBAPP_KEY` | API key for the webapp MISP server |
| `MISP_WEBAPP_VERIFYCERT` | Whether to verify the webapp MISP server's TLS certificate |

### Products

The Products tab covers how products and requirements are categorised and summarised. `PRODUCT_TYPES` defines the catalogue of CTI product types offered when creating a product. `DAILY_BRIEFING_TITLE_EXCLUSIONS` lists story titles or phrases that the daily briefing analyser should ignore when proposing stories. The five `FOCUS_POINTS_*` lists (geographies, sectors, technologies, threat types and threat actors) define the organisation-wide focus points used when previewing relevance against scraper events and when generating AI summaries. `THREAT_ACTOR_TYPES` is a small table of threat actor type names and descriptions, based on the ENISA taxonomy, used when classifying threat actors in products and requirements.

| Setting | Description |
|---|---|
| `PRODUCT_TYPES` | Catalogue of CTI product types offered when creating a product |
| `DAILY_BRIEFING_TITLE_EXCLUSIONS` | Story titles or phrases the daily briefing analyser should ignore |
| `FOCUS_POINTS_GEOGRAPHIES` | Organisation-wide geography focus points |
| `FOCUS_POINTS_SECTORS` | Organisation-wide sector focus points |
| `FOCUS_POINTS_TECHNOLOGIES` | Organisation-wide technology focus points |
| `FOCUS_POINTS_THREAT_TYPES` | Organisation-wide threat type focus points |
| `FOCUS_POINTS_THREAT_ACTORS` | Organisation-wide threat actor focus points |
| `THREAT_ACTOR_TYPES` | Threat actor type names and descriptions (ENISA taxonomy) |

Renaming a product type does not rename it in the stakeholder subscriptions already stored in MISP. The System tab carries a migration for the one rename that shipped with zsazsa ("Vulnerability exploitation advisory" to "Vulnerability advisory").

### System

The System tab holds six cards.

**MISP event distribution** sets `MISP_EVENT_DISTRIBUTION`, the distribution level given to every event zsazsa creates in the webapp MISP: stakeholders, PIRs, GIRs, RFIs and products. The default of 0 keeps them to your own organisation, which is the safe choice, since these events carry internal program data rather than shareable threat intelligence.

**Analyser** contains `POLL_WINDOW_HOURS` (how far back the analyser looks for new events on each run), `EVENT_LOG_RETENTION_DAYS` (how long rows in the `event_log` table are kept) and `PIPELINE_RUN_LOG_RETENTION_DAYS` (how long pipeline run history is kept). **Logging** sets `LOG_LEVEL`. **Web server** covers `HOSTNAME` and `PORT`, plus `SSL_ENABLED`, `SSL_CERT` and `SSL_KEY` for running the built-in server with TLS. After changing the port or SSL settings, restart the application for the change to take effect; the listener address itself is always `0.0.0.0` regardless of the `HOSTNAME` value, which is kept mainly for reference and for building links.

**Single sign-on** is described in its own section below. **Migration** lists the one-off maintenance scripts that rewrite existing data in MISP. Each one runs as a dry-run first and reports what it would change, then applies the change when you run it for real. The scripts are `scripts/make_zsazsa_tags_local.py` (re-attach `zsazsa:` namespace tags as local tags so they never sync to connected instances), `scripts/rename_vea_subscription_product.py` (rewrite the old VEA product name in stakeholder subscriptions) and `scripts/backfill_product_source_log.py` (record the source events of products created before source logging existed). Only these three can be launched from the page, and the browser only ever sends a migration id, never a path.

| Setting | Description |
|---|---|
| `MISP_EVENT_DISTRIBUTION` | Distribution level for events zsazsa creates: 0 your organisation, 1 this community, 2 connected communities, 3 all communities |
| `POLL_WINDOW_HOURS` | How far back the analyser looks for new events on each run |
| `EVENT_LOG_RETENTION_DAYS` | How long rows in the `event_log` table are kept |
| `PIPELINE_RUN_LOG_RETENTION_DAYS` | How long pipeline run history is kept |
| `LOG_LEVEL` | Logging verbosity |
| `HOSTNAME` | Hostname or IP shown for reference and used to build links |
| `PORT` | Port the application listens on |
| `SSL_ENABLED` | Whether the built-in server uses TLS |
| `SSL_CERT` | Path to the TLS certificate file |
| `SSL_KEY` | Path to the TLS private key file |

#### Single sign-on against MISP

zsazsa has no user accounts of its own. It identifies the analyst from MISP's own session: MISP (CakePHP) stores its sessions in Redis, and zsazsa reads the session referenced by MISP's session cookie straight out of that Redis instance. This only works when zsazsa is served under the same host as MISP, as described in the Apache section, because otherwise the browser never sends the cookie.

The cookie is named `MISP-<instance uuid>` and is therefore unique per install. You do not need to look it up: enable single sign-on and save, and zsazsa queries the MISP server for its instance UUID and stores the resulting name in `MISP_SESSION_COOKIE_NAME`. Set that value by hand only to override the detected one. The name is derived from, and the login redirect points at, the MISP server configured as `MISP_URL`.

With `MISP_SESSION_REDIRECT_TO_LOGIN` on, a visitor without a valid MISP session is redirected to MISP's login page. With it off, such requests fall back to the `admin@admin.test` identity, which is the right setting for a development instance and the wrong one for a shared deployment. Users seen through a session are recorded and listed on the community page. The public indicator feed URL and the Diamond Model image endpoint stay reachable without a session, since they are capability URLs meant to be handed out.

| Setting | Description |
|---|---|
| `MISP_SESSION_REDIRECT_TO_LOGIN` | Redirect visitors without a MISP session to MISP's login page |
| `MISP_SESSION_COOKIE_NAME` | MISP's session cookie name, detected automatically when left empty |
| `MISP_SESSION_REDIS_HOST` | Host of the Redis instance MISP stores its sessions in |
| `MISP_SESSION_REDIS_PORT` | Port of that Redis instance |
| `MISP_SESSION_REDIS_DB` | Database index MISP uses for sessions |
| `MISP_SESSION_REDIS_USERNAME` | Username, when the instance uses ACLs |
| `MISP_SESSION_REDIS_PASSWORD` | Password, if the instance requires one |

### Prompts

This tab lists every prompt template file found in `zsazsaprompts/`. New prompt files can also be created from here. Every prompt is parsed back into structured data, so the wording is yours to change but the output contract is not.

| Prompt file | Constraint |
|---|---|
| `summarise_misp_report` | Must keep its `**Targeted sector:**`, `**Geographic scope:**`, `**MITRE ATT&CK techniques:**`, `**Threat actor:**` and `**Vendor/Technology:**` headings |
| `flash_intel_generate` | Must keep its overall section and field structure, since the "Generate AI draft" feature reads it line by line |
| `flash_intel_relevance` | Must keep returning the `relevant`, `matched_focus_points`, `source_type`, `confidence` and `reason` JSON keys |
| `daily_briefing_story` | Must keep the five-line structure followed by the `Threat actor type: <type>` line, which is parsed out separately |
| `daily_briefing_relevance` | Must keep returning only the `include` and `reason` JSON keys |
| `daily_briefing_overlap` | Must keep returning the `summary` and `overlaps` JSON structure, with 1-based story indexes |
| `vea_draft`, `threat_actor_profile_draft`, `threat_landscape_trends`, `product_qa_review` | Must keep returning the JSON keys they list, since each key fills a named form field or panel |

Changing these headings or structure will cause the corresponding feature to fail silently.

Three prompts back the drafting and review buttons on the products themselves. `threat_actor_profile_draft` fills the narrative fields of a threat actor profile from the selected actors, the MISP galaxy context and any notes already on the form, and only ever writes into fields the analyst left empty. `threat_landscape_trends` drafts the threat landscape report from the collection events queued for it, counting the events behind each trend and leaving `[ANALYST]` markers where the organisational judgement belongs. `product_qa_review` backs the "QA check against source" button on flash intel alert and vulnerability advisory drafts: it audits the draft against the report content of its source events and returns a verdict with the claims a reviewer should fix before publishing.

### AI

The AI tab starts with the LLM providers card, holding one section per provider. **OpenAI** takes an API key and a default model, and shows its token usage. **Local LLM** takes the network location of a server that speaks the OpenAI API, an API key for servers that require one, and its own default model. The network location is the base URL of the endpoint, for example `http://127.0.0.1:11434` for a local [Ollama](https://ollama.com/); the `/v1` path is appended automatically when it is missing. Ollama ignores the API key, so leave it empty unless the server is behind a proxy that checks it.

Each provider has its own enable switch, and one provider is marked as the default with the "Default provider" button. The default is used by any feature that does not choose a provider itself, and marking one provider as default clears the mark on the other. A provider cannot be disabled while features still point at it.

Below the providers, a table lists each AI-assisted feature (for example summarising a report or generating a Flash Intel Alert draft) with the provider it uses, an optional per-feature model override, a sampling temperature, and the prompt file it uses. An empty model field means the feature uses the default model of its provider. An empty temperature leaves sampling to the model, which for a locally hosted model can mean a value as high as 1.0; since almost every feature here is parsed back into structured data, a low temperature between 0 and 0.2 keeps that output stable. OpenAI reasoning models only accept their own default, so the temperature is not sent to them. This feature-level configuration is stored separately, in `data/ai_features.json`, rather than in `config/__init__.py`, and is therefore untouched by a Settings save and not covered by the config backup.

Because these features send raw MISP event content to the configured LLM, only connect AI features to MISP servers you trust, and review AI-generated output before publishing it. A local LLM keeps that content inside your own infrastructure.

Token usage is recorded per provider in the `llm_usage` table of the analyser database and shown in each provider's section. Rows written before local LLM support are counted as OpenAI usage.

Reasoning models spend part of their token budget thinking before answering, and the per-feature budgets are sized for a straight answer. zsazsa asks local servers to skip the thinking step, which Ollama honours; on a server that ignores the request, a reasoning model can spend the whole budget and return an empty answer. That case is logged with the model, the finish reason and the budget, and reported in the interface rather than saved.

| Setting | Description |
|---|---|
| `LLM_DEFAULT_PROVIDER` | Provider used by features that do not choose one: `openai` or `local` |
| `OPENAI_ENABLED` | Whether OpenAI can be used by AI features |
| `OPENAI_API_KEY` | API key used for OpenAI-based AI features |
| `OPENAI_MODEL` | Default OpenAI model used by AI features that don't specify their own |
| `LOCAL_LLM_ENABLED` | Whether the local LLM can be used by AI features |
| `LOCAL_LLM_URL` | Base URL of the OpenAI-compatible endpoint, for example `http://127.0.0.1:11434` |
| `LOCAL_LLM_API_KEY` | API key for the local endpoint, empty when it needs none |
| `LOCAL_LLM_MODEL` | Default local model used by AI features that don't specify their own |
| Per-feature provider, model, temperature and prompt (`data/ai_features.json`) | Overrides for each AI-assisted feature |

### Context elements

This tab covers zsazsa's MISP tags and tag presets. The entity type markers `TAG_STAKEHOLDER`, `TAG_PIR`, `TAG_GIR` and `TAG_RFI` identify the corresponding zsazsa entities in MISP. The product classification tags `TAG_FLASH_INTEL`, `TAG_VEA`, `TAG_BRIEFING`, `TAG_TLR`, `TAG_INDICATOR_FEED` and `TAG_THREAT_ACTOR_PROFILE` mark products by type. `SCRAPER_MARKER_TAG` is the tag the analyser and the data collection page use to recognise events coming from the misp-scraper instance, `TAG_COLLECTION_FOLLOWUP` flags collection items for analyst follow-up, and `TAG_COLLECTION_DISMISSED` marks events from another MISP server that an analyst set aside, since their workflow state belongs to that server. `RECOMMENDED_ACTIONS_IMMEDIATE` and `RECOMMENDED_ACTIONS_NEAR_TERM` are organisation-wide presets offered as one-click insert buttons in the Flash Intel and VEA wizards. Finally, `COLLECTION_TAG_STRIP_PREFIXES` and `COLLECTION_TAG_HIDE_PREFIXES` control how tags are shortened or hidden when displaying events on the data collection page.

Everything zsazsa writes in the `zsazsa:` namespace is attached as a local tag, so it never syncs to connected MISP instances.

| Setting | Description |
|---|---|
| `TAG_STAKEHOLDER` | Marks stakeholder events |
| `TAG_PIR` | Marks PIR events |
| `TAG_GIR` | Marks GIR events |
| `TAG_RFI` | Marks RFI events |
| `TAG_FLASH_INTEL` | Marks published Flash Intel Alert products |
| `TAG_VEA` | Marks published VEA products |
| `TAG_BRIEFING` | Marks published daily briefing products |
| `TAG_TLR` | Marks published threat landscape report products |
| `TAG_INDICATOR_FEED` | Marks indicator feed products |
| `TAG_THREAT_ACTOR_PROFILE` | Marks threat actor profile products |
| `SCRAPER_MARKER_TAG` | Identifies events coming from the misp-scraper instance |
| `TAG_COLLECTION_FOLLOWUP` | Flags collection items for analyst follow-up |
| `TAG_COLLECTION_DISMISSED` | Marks events from another MISP server that an analyst set aside |
| `RECOMMENDED_ACTIONS_IMMEDIATE` | Preset immediate actions offered as one-click inserts |
| `RECOMMENDED_ACTIONS_NEAR_TERM` | Preset near-term actions offered as one-click inserts |
| `COLLECTION_TAG_STRIP_PREFIXES` | Tag prefixes shortened on the data collection page |
| `COLLECTION_TAG_HIDE_PREFIXES` | Tag prefixes hidden on the data collection page |

The tab also shows the **product source markers**, the local tags applied to a scraper event when it is used as the source of a product: `zsazsa:product="daily-briefing"`, `zsazsa:product="flash-intel"`, `zsazsa:product="vea"` and `zsazsa:product="threat-landscape-report"`. These are fixed in the code, shown read-only with a link to browse the tagged events in MISP, and are not configuration settings.

### Notifications

The Notifications tab manages `NOTIFICATION_CHANNELS`, a list of named channels, and `FLOWINTEL_INSTANCES`. A **Mattermost** channel carries a webhook URL, an **email** channel carries a recipient address. Stakeholders are subscribed to one or more of these channels under Stakeholder management, so published products and requirement updates reach the right destinations. For backwards compatibility, the legacy `MATTERMOST_ENABLED` and `MATTERMOST_WEBHOOK_URL` settings are derived automatically from the first enabled Mattermost channel and do not need to be set by hand.

Email channels share one SMTP server, configured in the same tab and stored in the `SMTP_*` settings. The "Test connection" button checks the SMTP host and credentials without sending anything; each email channel also has a button to send a test message to its recipient. For Gmail and similar providers, use an account-specific app password rather than the normal account password.

**Flowintel** instances are the third kind of destination. Each instance carries a name, URL, API key, TLS verification setting and enable switch, and can be reached with a connectivity test. Per instance, a table maps CTI products to Flowintel case templates: enable a product, choose the case template and optionally an initial task, and publishing that product to a stakeholder subscribed to the instance creates the case. Flash intel alerts and vulnerability advisories are the products that can be mapped. Templates and tasks are read live from the Flowintel instance, so the instance must be reachable while you configure it.

| Setting | Description |
|---|---|
| `NOTIFICATION_CHANNELS` | Named channels. Mattermost: name, URL, TLS verification, enabled flag. Email: name, recipient address, enabled flag |
| `MATTERMOST_ENABLED` (legacy) | Derived automatically from the first enabled Mattermost channel |
| `MATTERMOST_WEBHOOK_URL` (legacy) | Derived automatically from the first enabled Mattermost channel |
| `SMTP_HOST`, `SMTP_PORT` | SMTP server address and port (for example `smtp.gmail.com` and `587`) |
| `SMTP_USE_TLS` | Use STARTTLS on the connection |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | SMTP credentials (use an app password where the provider requires one) |
| `SMTP_FROM` | From address shown on outgoing mail |
| `FLOWINTEL_INSTANCES` | Flowintel instances: name, URL, API key, TLS verification, enabled flag and the per-product `case_templates` mapping |

Delivery itself runs as a background job, so publishing returns immediately and the outcome shows up in the job badge rather than holding the browser on a slow SMTP host or an unreachable Flowintel instance.

### Styling

The Styling tab covers branding used in PDF exports and notifications: `BRAND_COMPANY` and `BRAND_DEPARTMENT` (shown in PDF headers and footers), `BRAND_LOGO` (uploaded here and stored in `data/uploads/`, with the setting holding just the file name), and the three brand colours `BRAND_COLOR_1`, `BRAND_COLOR_2` and `BRAND_COLOR_3`, used throughout generated PDFs and Mattermost message styling.

The same tab also chooses the **UI theme**, which re-colours the whole interface and takes effect on the next page load. Three themes ship with zsazsa: **Overmind** (a MISP-style teal theme with a top navigation bar, the default on a new install), **UiBeta** (a MISP-style light theme, also top navigation), and **Zsazsa legacy** (the original navy theme with the side menu).

| Setting | Description |
|---|---|
| `THEME` | UI theme: `overmind` (default), `uibeta` or `default` (Zsazsa legacy navy) |
| `BRAND_COMPANY` | Company name shown in PDF headers and footers |
| `BRAND_DEPARTMENT` | Department name shown in PDF headers and footers |
| `BRAND_LOGO` | File name of the logo in `data/uploads/`, used in generated PDFs and notifications |
| `BRAND_COLOR_1` | Primary brand colour |
| `BRAND_COLOR_2` | Secondary brand colour |
| `BRAND_COLOR_3` | Tertiary brand colour |

### Settings not exposed in the interface

A small number of settings are only ever set by editing `config/__init__.py` directly. `SECRET_KEY` is the Flask session secret and should be unique per installation; it can also be supplied through the environment, which takes precedence over the config file. `STATE_FILE`, `DB_FILE` and `LOG_FILE` are filesystem paths for the analyser state, the SQLite database and the log file respectively. All four are carried over unchanged when the configuration is saved from the interface. `COLLECTION_SOURCES` is rebuilt automatically from the scraper and the additional MISP servers every time the configuration is loaded, so it should not be edited by hand.

`COLLECTION_CACHE_INTERVAL` is the exception that needs care. It sets how many minutes the data collection cache worker waits between refresh cycles, defaulting to 15, and it is not part of the file the Settings page writes, so a save from the interface removes it and the default applies again.

| Setting | Description |
|---|---|
| `SECRET_KEY` | Flask session secret, should be unique per installation |
| `STATE_FILE` | Path to the analyser state file |
| `DB_FILE` | Path to the SQLite database holding the analyser log, audit log, organisations and SSO users |
| `LOG_FILE` | Path to the log file, rotated at 5 MB with three generations kept |
| `COLLECTION_CACHE_INTERVAL` | Minutes between data collection cache refreshes (default 15), dropped on a Settings save |
| `COLLECTION_SOURCES` | Auto-derived list of collection sources, do not edit by hand |

The data collection cache lives in `data/collection_cache.db`, whose path is fixed in the code and not configurable.

### Background jobs

Work that takes minutes rather than seconds runs on a background thread, so the browser is free to go elsewhere while it finishes: analyser runs started from the dashboard, AI summaries started from data collection, product notification delivery on publish, and the scheduled analyser and mailbox runs started from cron. Their progress is kept in Redis, which is what lets the job badge in the top bar still show a run that someone else started, or one you started before reloading the page. Finished runs are also written to the analyser database and listed under Reporting > Pipeline.

Without Redis the app falls back to keeping the jobs in the process memory: everything still works, but the state is lost on restart and is not shared between processes, which also means a cron analyser run is invisible to the web app. Any Redis instance will do, including the one MISP already uses, as long as the database number is not shared with something that would trip over an extra `zsazsa:jobs` key.

These settings are not written by the Settings page. Add them to `config/__init__.py` by hand, and add them again after a save from the interface, which regenerates the file without them and drops the app back to `127.0.0.1:6379`.

| Setting | Description |
|---|---|
| `JOB_REDIS_HOST` | Redis host holding the job state (default `127.0.0.1`) |
| `JOB_REDIS_PORT` | Redis port (default `6379`) |
| `JOB_REDIS_DB` | Redis database number (default `0`) |
| `JOB_REDIS_USERNAME` | Username, when the instance uses ACLs |
| `JOB_REDIS_PASSWORD` | Password, if the instance requires one |
| `JOB_REDIS_KEY` | Hash the jobs are stored under (default `zsazsa:jobs`) |

## Creating data collection sources

The `/config/sources/` page is where every source the analyser and the data collection view can pull from is configured: the misp-scraper connection, the queue manual sources push into, any additional MISP servers, manual collection sources for material that is not collected automatically, and the IMAP mailboxes newsletters arrive in.

### MISP scraper connection

The "MISP scraper (collection pipeline)" card holds the connection to the misp-scraper instance: its URL, API key, whether to verify TLS, the maximum number of events to pull per run (`MISP_SCRAPER_LIMIT`), and how many days back to pull (`MISP_SCRAPER_SINCE_DAYS`). This source is always active and always appears on the Data collection page. The "Test connection" button checks the URL and API key against the MISP server, and "Pull estimate" reports how many events currently match the scraper marker tag, which is itself configured on the Context elements tab of `/config`. The "Show query" link displays the underlying `misp.search()` call for reference.

| Field | Description |
|---|---|
| URL | Address of the misp-scraper MISP instance (`MISP_URL`) |
| API key | API key for the scraper MISP instance (`MISP_KEY`) |
| Verify TLS | Whether to verify the scraper MISP server's TLS certificate (`MISP_VERIFYCERT`) |
| Max events | Maximum number of events pulled per run (`MISP_SCRAPER_LIMIT`) |
| Events from last (days) | Only pull scraper events from the last N days (`MISP_SCRAPER_SINCE_DAYS`); 0 disables the date window |

**Why both "Max events" and "Events from last (days)" matter.** The cache worker fetches up to `MISP_SCRAPER_LIMIT` marker-tagged events in a single page, so the data collection view never holds more than that many scraper events. Without a date window, once the scraper accumulates more tagged events than the limit, the surplus is dropped from the cache and may include the most recent events, so newly scraped items stop appearing on the Data collection page even though the refresh log reports a successful run (for example `scraper done - 800 events` every cycle, exactly at the limit). The tell-tale sign is a refresh count that sits permanently at the configured limit. `MISP_SCRAPER_SINCE_DAYS` avoids this by restricting the pull to a recent window, so growth past the limit drops the oldest events rather than hiding the newest; keep the window small enough that the tagged events within it stay under `MISP_SCRAPER_LIMIT`. Compare "Pull estimate" (or filter the scraper MISP by `SCRAPER_MARKER_TAG`) against the limit to size both settings. Setting the window to 0 restores the old pull-by-limit behaviour.

### Manual sources pushing to scraper

Some manual sources do not store events directly but hand article links to the misp-scraper, which fetches and creates them. This is how the newsletter importer works: the selected article URLs are published to the scraper's Redis channel, and the events that come back behave like ordinary scraper events.

| Field | Description |
|---|---|
| Redis host | Host of the misp-scraper Redis (`SCRAPER_REDIS_HOST`) |
| Port | Redis port (`SCRAPER_REDIS_PORT`) |
| Password | Redis password, if the instance requires one (`SCRAPER_REDIS_PASSWORD`) |
| Channel | Publish/subscribe channel the scraper subscribes to (`SCRAPER_REDIS_CHANNEL`, default `urls`) |

The scraper's own `subscribe` service must be running against this Redis. Publishing is fire and forget, so a channel nobody listens on loses the URLs silently.

### Additional MISP servers

The "Other MISP servers" card lists any extra MISP instances configured in `MISP_SERVERS`, such as community MISP servers. Use "Add MISP server" to create a new entry, then fill in a label, an optional ID (used as a URL slug, generated from the label if left blank), the server URL, API key and TLS verification setting. Only published events are fetched from these servers. Filtering is controlled with three tag fields, tags that an event must have any of, tags it must have all of, and tags that exclude it, plus an optional organisation filter that can either restrict results to a set of organisation UUIDs or exclude them. "Events from last (days)" sets how far back to look based on the event date, and "Max events" caps how many events are pulled. As with the scraper, each server can be tested, given a pull estimate, and have its query previewed before saving. Each server is saved individually with its own "Save server" button, can be enabled or disabled with the power icon, and can be deleted. Disabling or deleting a server that is referenced by a PIR or GIR as a collection source will warn you first, since the reference itself is not removed.

| Field | Description |
|---|---|
| Label | Display name for the server |
| ID | URL slug, generated from the label if left blank |
| URL | Address of the MISP server |
| API key | API key for the MISP server |
| Verify TLS | Whether to verify the server's TLS certificate |
| Tags OR | Fetch events with any of these tags |
| Tags AND | Fetch events with all of these tags |
| Tags NOT | Exclude events with any of these tags |
| Organisation filter | Include only, or exclude, events from the given organisation UUIDs |
| Events from last (days) | How far back to look, based on the event date |
| Max events | Maximum number of events pulled per query |
| Enabled | Whether the server is active and offered as a filter option |

### Manual collection sources

The "Manual sources" card lists collection sources that are not MISP servers, for example a newsletter, a partner portal, or any other feed an analyst monitors by hand. Selecting "Add manual source" opens a form with a name (shown in PIR and GIR collection source dropdowns), an owner (the person or team responsible for monitoring it), a location (a URL, file path or physical location), a description of what the source covers and why it matters, and a source reliability rating on the Admiralty scale.

| Field | Description |
|---|---|
| Name | Name shown in PIR and GIR collection source dropdowns |
| Owner | Person or team responsible for monitoring the source |
| Location | URL, file path or physical location of the source |
| Description | What the source covers and why it matters |
| Source reliability | Admiralty scale rating, applied as an `admiralty-scale:source-reliability` tag |

Each manual source is itself stored as a `zsazsa-collection-source` event in the webapp MISP, and can be edited, enabled or disabled, or deleted from the list. As with additional MISP servers, disabling or deleting a manual source that is referenced by a PIR or GIR will prompt for confirmation first, since the reference itself is not removed.

### IMAP mailboxes

The "IMAP mailboxes" card configures mailboxes that `run_imap_collector.py` polls for forwarded newsletters (covered in "Collecting newsletters from a mailbox (IMAP)" in [README.md](README.md)). The configuration nests: a mailbox holds the connection, and within it one or more newsletter sources say which mail to pick up and how to treat it. Everything is stored in `config.IMAP_SOURCES`.

The mailbox itself:

| Field | Description |
|---|---|
| Mailbox name | Display name for the mailbox |
| IMAP host / Port / SSL | Connection to the mail server (default port 993 with SSL) |
| Folder | Mailbox folder to read (default `INBOX`) |
| Username / Password | Mailbox credentials (use an app password where the provider requires one) |
| Enabled | Whether the mailbox is polled |

Each newsletter source inside it:

| Field | Description |
|---|---|
| Name | Display name, and the collection source recorded on the events created from it |
| Parser | Which newsletter parser to apply to matched mail |
| Mode | `Automatic` (push articles to the scraper immediately) or `Manual review` (park for human approval) |
| Match subjects | Subject substrings, one per line; a match on any one selects the mail |
| Match senders | Sender substrings, one per line; matched against the From header and a forwarded message's original sender |
| Reliability | Admiralty scale rating recorded for the source |
| Enabled | Whether this source is applied when the mailbox is polled |

"Test connection" opens the mailbox with the entered settings without reading or changing any mail. Polling never deletes mail; a message is flagged with the `zsazsaProcessed` IMAP keyword only once it has been archived, so a failure retries on the next run instead of losing the newsletter.

## Optional post-installation steps

The MITRE ATT&CK technique list used in product forms and briefing stories is read from `data/mitre-attack-pattern.json`. When that file is missing the list is fetched from the MISP galaxy instead, which works but costs a query. Populate and refresh the local cache with:

```bash
venv/bin/python scripts/fetch_mitre_galaxy.py
```

Re-run it periodically to pick up new techniques. The application notices the new file without a restart.
