# Installing and configuring zsazsa

This guide covers everything needed to stand up zsazsa: the infrastructure it depends on, installation, configuration, running it, and deploying it. For what zsazsa does and how analysts use it, see [README.md](README.md).

## What you need before installing

zsazsa sits on top of MISP and requires the following infrastructure to be in place first:

- **A MISP server to store CTI program data.** This is where zsazsa saves its objects: stakeholders, PIRs, GIRs, flash intel alerts, advisories, briefings, and so on. This is the server you point `MISP_WEBAPP_URL` at.

- **A MISP server running misp-scraper.** The scraper feeds threat events into a MISP instance that zsazsa polls for the data collection view and the analyser pipeline. This is the server you point `MISP_URL` at. It can be the same server as above.

- **One or more additional MISP servers (optional but recommended).** zsazsa can pull threat events from other MISP instances configured under Collection sources. These act as supplementary intelligence feeds. Ideally they are separate servers from your own MISP, such as partner-operated or community instances.

zsazsa does not install MISP or misp-scraper. Follow the official installation guides for those projects first.

## Installation

Installation is recommended inside the MISP custom application directory (create it if it does not already exist with `mkdir /var/www/MISP/misp-custom ; chown www-data:www-data /var/www/MISP/misp-custom`) so that it runs under the same web user as MISP. On Ubuntu this means installing as `www-data`:

```bash
cd /var/www/MISP/misp-custom
sudo -u www-data git clone <this-repo> zsazsa
cd zsazsa
sudo -u www-data bash docs/install.sh
```

The installer creates a `venv` in the project root, installs the Python dependencies, prepares the data directory, and creates `config/__init__.py` if it is missing.

After installation, edit `config/__init__.py` and set your MISP URL and API key settings. If you want to run zsazsa as a systemd service, use `docs/zsazsa.service.template` as your starting point.

## Configuration

Main runtime settings are in `config/__init__.py`. You can configure:

- scraper and webapp MISP connections
- optional extra MISP sources for the collection browser
- manual collection sources (a structured registry with name, owner, location, description, enable/disable, and an Admiralty scale reliability rating, each backed by a MISP event)
- the product type catalogue
- recommended immediate and near-term actions shown as presets in the Flash Intel and VEA wizards
- notification channels (named Mattermost webhooks and email recipients, each with a name and enable/disable toggle, plus the shared SMTP server used for email)
- the analyser polling window and marker tag
- log settings and file paths

The configuration page organises settings across tabs (Connections, Products, System, Prompts, AI, Context elements, Notifications and Styling). Collection sources, namely the MISP scraper connection, additional MISP servers and manual sources, are managed at `/config/sources/`. MISP connections can be tested live, each server entry can be saved individually, and manual sources have a per-source enable/disable with an in-use guard against PIR/GIR references. The config file is backed up automatically before each save. The full per-tab reference is in [Configuration settings](#configuration-settings) below.

## Running the application

```bash
source venv/bin/activate
python run_webapp.py
```

The application listens on `http://0.0.0.0:5000` by default. Open it in a browser at the IP address or hostname of your server.

Run the analyser pipeline (typically via cron):

```bash
source venv/bin/activate
python run_analyser.py
```

The hostname zsazsa listens on, as well as the port, are configurable in `config.py`:

```python
HOSTNAME = 'zsazsa.example.com'   # or an IP address
PORT = 5000
```

These values can also be changed from the Settings page in the web app (System tab). After saving, restart the application for the port change to take effect (the `HOSTNAME` value is stored for reference; the listener address is always `0.0.0.0`).

## Production deployment behind Apache

zsazsa is designed to run alongside MISP and can be served under a subpath of the MISP Apache virtual host, for example `https://misp.example.com/zsazsa`. The application adapts to any subpath automatically, so `/cti`, `/cti-program`, or any other value works without changing the application.

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

ProxyPass        /zsazsa  http://127.0.0.1:5000/
ProxyPassReverse /zsazsa  http://127.0.0.1:5000/
```

The value in `RequestHeader set X-Forwarded-Prefix` must match the path used in `ProxyPass` and `ProxyPassReverse`. To use a different subpath, change all three occurrences. No application restart is needed for subpath changes, only an Apache reload (`systemctl reload apache2`).

The application reads `X-Forwarded-Prefix` at runtime to construct links and AJAX call paths, and reads `X-Forwarded-Proto` to build correct `https://` URLs in Mattermost notifications and product preview links. When run directly without a proxy, both headers are absent and the application behaves exactly as before.

## Upgrading

Go to the installation directory and pull as the web user:

```bash
cd /var/www/MISP/misp-custom/zsazsa
sudo -u www-data git pull
```

Then restart the service to pick up the changes:

```bash
sudo systemctl restart zsazsa.service
```

## Configuration settings

Almost all runtime settings are in `config/__init__.py`, and most of them can be changed from the web interface without editing the file directly. The main settings page is at `/config` and groups settings across eight tabs: **Connections**, **Products**, **System**, **Prompts**, **AI**, **Context elements**, **Notifications** and **Styling**. A few settings, namely the MISP scraper connection, the list of additional **MISP servers**, and the manual **collection sources**, are managed on a separate page at `/config/sources/`, covered in [Creating data collection sources](#creating-data-collection-sources) below. Whichever page you save from, the previous version of `config/__init__.py` is copied to `config/__init__.py.backup` first.

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

### System

The System tab is split into three cards. The Analyser card contains `POLL_WINDOW_HOURS` (how far back the analyser looks for new events on each run), `EVENT_LOG_RETENTION_DAYS` (how long rows in the `event_log` table are kept) and `PIPELINE_RUN_LOG_RETENTION_DAYS` (how long pipeline run history is kept). The Logging card sets `LOG_LEVEL`. The Web server card covers `HOSTNAME` and `PORT`, plus `SSL_ENABLED`, `SSL_CERT` and `SSL_KEY` for running the built-in server with TLS. After changing the port or SSL settings, restart the application for the change to take effect; the listener address itself is always `0.0.0.0` regardless of the `HOSTNAME` value, which is kept mainly for reference and for building links.

| Setting | Description |
|---|---|
| `POLL_WINDOW_HOURS` | How far back the analyser looks for new events on each run |
| `EVENT_LOG_RETENTION_DAYS` | How long rows in the `event_log` table are kept |
| `PIPELINE_RUN_LOG_RETENTION_DAYS` | How long pipeline run history is kept |
| `LOG_LEVEL` | Logging verbosity |
| `HOSTNAME` | Hostname or IP shown for reference and used to build links |
| `PORT` | Port the application listens on |
| `SSL_ENABLED` | Whether the built-in server uses TLS |
| `SSL_CERT` | Path to the TLS certificate file |
| `SSL_KEY` | Path to the TLS private key file |

### Prompts

This tab lists every prompt template file found in `zsazsaprompts/`. New prompt files can also be created from here. Two prompts have a strict output format that the application parses back into structured data:

| Prompt file | Constraint |
|---|---|
| `summarise_misp_report` | Must keep its `**Targeted sector:**`, `**Geographic scope:**`, `**MITRE ATT&CK techniques:**`, `**Threat actor:**` and `**Vendor/Technology:**` headings |
| `flash_intel_generate` | Must keep its overall section and field structure, since the "Generate AI draft" feature reads it line by line |
| `vea_draft`, `threat_actor_profile_draft`, `threat_landscape_trends`, `product_qa_review` | Must keep returning the JSON keys they list, since each key fills a named form field or panel |

Changing these headings or structure will cause the corresponding feature to fail silently.

Three prompts back the drafting and review buttons on the products themselves. `threat_actor_profile_draft` fills the narrative fields of a threat actor profile from the selected actors, the MISP galaxy context and any notes already on the form, and only ever writes into fields the analyst left empty. `threat_landscape_trends` drafts the threat landscape report from the collection events queued for it, counting the events behind each trend and leaving `[ANALYST]` markers where the organisational judgement belongs. `product_qa_review` backs the "QA check against source" button on flash intel alert and vulnerability advisory drafts: it audits the draft against the report content of its source events and returns a verdict with the claims a reviewer should fix before publishing.

### AI

The AI tab starts with the LLM providers card, holding one section per provider. **OpenAI** takes an API key and a default model, and shows its token usage. **Local LLM** takes the network location of a server that speaks the OpenAI API, an API key for servers that require one, and its own default model. The network location is the base URL of the endpoint, for example `http://127.0.0.1:11434` for a local [Ollama](https://ollama.com/); the `/v1` path is appended automatically when it is missing. Ollama ignores the API key, so leave it empty unless the server is behind a proxy that checks it.

Each provider has its own enable switch, and one provider is marked as the default with the "Default provider" button. The default is used by any feature that does not choose a provider itself, and marking one provider as default clears the mark on the other. A provider cannot be disabled while features still point at it.

Below the providers, a table lists each AI-assisted feature (for example summarising a report or generating a Flash Intel Alert draft) with the provider it uses, an optional per-feature model override, a sampling temperature, and the prompt file it uses. An empty model field means the feature uses the default model of its provider. An empty temperature leaves sampling to the model, which for a locally hosted model can mean a value as high as 1.0; since almost every feature here is parsed back into structured data, a low temperature between 0 and 0.2 keeps that output stable. OpenAI reasoning models only accept their own default, so the temperature is not sent to them. This feature-level configuration is stored separately, in `data/ai_features.json`, rather than in `config/__init__.py`.

Because these features send raw MISP event content to the configured LLM, only connect AI features to MISP servers you trust, and review AI-generated output before publishing it. A local LLM keeps that content inside your own infrastructure.

Token usage is recorded per provider in the `llm_usage` table of the analyser database and shown in each provider's section. Rows written before local LLM support are counted as OpenAI usage.

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

Reasoning models spend part of their token budget thinking before answering, and the per-feature budgets are sized for a straight answer. zsazsa asks local servers to skip the thinking step, which Ollama honours; on a server that ignores the request, a reasoning model can spend the whole budget and return an empty answer. That case is logged with the model, the finish reason and the budget, and reported in the interface rather than saved.
| Per-feature model and prompt (`core/ai_config.py`) | Optional model override and prompt file for each AI-assisted feature |

### Context elements

This tab covers zsazsa's MISP tags and tag presets. The entity type markers `TAG_STAKEHOLDER`, `TAG_PIR`, `TAG_GIR` and `TAG_RFI` identify the corresponding zsazsa entities in MISP. The product classification tags `TAG_FLASH_INTEL`, `TAG_VEA`, `TAG_BRIEFING`, `TAG_TLR`, `TAG_INDICATOR_FEED` and `TAG_THREAT_ACTOR_PROFILE` mark products by type. `SCRAPER_MARKER_TAG` is the tag the analyser and the data collection page use to recognise events coming from the misp-scraper instance, and `TAG_COLLECTION_FOLLOWUP` flags collection items for analyst follow-up. `RECOMMENDED_ACTIONS_IMMEDIATE` and `RECOMMENDED_ACTIONS_NEAR_TERM` are organisation-wide presets offered as one-click insert buttons in the Flash Intel and VEA wizards. Finally, `COLLECTION_TAG_STRIP_PREFIXES` and `COLLECTION_TAG_HIDE_PREFIXES` control how tags are shortened or hidden when displaying events on the data collection page.

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
| `RECOMMENDED_ACTIONS_IMMEDIATE` | Preset immediate actions offered as one-click inserts |
| `RECOMMENDED_ACTIONS_NEAR_TERM` | Preset near-term actions offered as one-click inserts |
| `COLLECTION_TAG_STRIP_PREFIXES` | Tag prefixes shortened on the data collection page |
| `COLLECTION_TAG_HIDE_PREFIXES` | Tag prefixes hidden on the data collection page |

### Notifications

The Notifications tab manages `NOTIFICATION_CHANNELS`, a list of named channels. Each channel has a type: a **Mattermost** channel carries a webhook URL, an **email** channel carries a recipient address. Stakeholders are subscribed to one or more of these channels under Stakeholder management, so published products and requirement updates reach the right destinations. For backwards compatibility, the legacy `MATTERMOST_ENABLED` and `MATTERMOST_WEBHOOK_URL` settings are derived automatically from the first enabled Mattermost channel and do not need to be set by hand.

Email channels share one SMTP server, configured in the same tab and stored in the `SMTP_*` settings. The "Test connection" button checks the SMTP host and credentials without sending anything; each email channel also has a button to send a test message to its recipient. For Gmail and similar providers, use an account-specific app password rather than the normal account password.

| Setting | Description |
|---|---|
| `NOTIFICATION_CHANNELS` | Named channels. Mattermost: name, URL, TLS verification, enabled flag. Email: name, recipient address, enabled flag |
| `MATTERMOST_ENABLED` (legacy) | Derived automatically from the first enabled Mattermost channel |
| `MATTERMOST_WEBHOOK_URL` (legacy) | Derived automatically from the first enabled Mattermost channel |
| `SMTP_HOST`, `SMTP_PORT` | SMTP server address and port (for example `smtp.gmail.com` and `587`) |
| `SMTP_USE_TLS` | Use STARTTLS on the connection |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | SMTP credentials (use an app password where the provider requires one) |
| `SMTP_FROM` | From address shown on outgoing mail |

### Styling

The Styling tab covers branding used in PDF exports and notifications: `BRAND_COMPANY` and `BRAND_DEPARTMENT` (shown in PDF headers and footers), `BRAND_LOGO` (uploaded here and stored under the application's static files), and the three brand colours `BRAND_COLOR_1`, `BRAND_COLOR_2` and `BRAND_COLOR_3`, used throughout generated PDFs and Mattermost message styling.

The same tab also chooses the **UI theme**, which re-colours the whole interface and takes effect on the next page load. Three themes ship with zsazsa: **Overmind** (a MISP-style teal theme with a top navigation bar, the default on a new install), **UiBeta** (a MISP-style light theme, also top navigation), and **Zsazsa legacy** (the original navy theme with the side menu).

| Setting | Description |
|---|---|
| `THEME` | UI theme: `overmind` (default), `uibeta` or `default` (Zsazsa legacy navy) |
| `BRAND_COMPANY` | Company name shown in PDF headers and footers |
| `BRAND_DEPARTMENT` | Department name shown in PDF headers and footers |
| `BRAND_LOGO` | Logo image used in generated PDFs and notifications |
| `BRAND_COLOR_1` | Primary brand colour |
| `BRAND_COLOR_2` | Secondary brand colour |
| `BRAND_COLOR_3` | Tertiary brand colour |

### Settings not exposed in the interface

A small number of settings are only ever set by editing `config/__init__.py` directly. `SECRET_KEY` is the Flask session secret and should be unique per installation. `STATE_FILE`, `DB_FILE` and `LOG_FILE` are filesystem paths for the analyser state, the SQLite database and the log file respectively. `COLLECTION_SOURCES` is rebuilt automatically from the scraper, the additional MISP servers and the manual collection sources every time the configuration is loaded, so it should not be edited by hand.

| Setting | Description |
|---|---|
| `SECRET_KEY` | Flask session secret, should be unique per installation |
| `STATE_FILE` | Path to the analyser state file |
| `DB_FILE` | Path to the SQLite database |
| `LOG_FILE` | Path to the log file |
| `COLLECTION_SOURCES` | Auto-derived list of collection sources, do not edit by hand |

## Creating data collection sources

The `/config/sources/` page is where every source the analyser and the data collection view can pull from is configured: the misp-scraper connection, any additional MISP servers, and manual collection sources for material that is not collected automatically.

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

The "IMAP mailboxes" card configures mailboxes that `run_imap_collector.py` polls for forwarded newsletters (covered in "Collecting newsletters from a mailbox" in [README.md](README.md)). Each entry is stored in `config.IMAP_SOURCES`.

| Field | Description |
|---|---|
| Name | Display name for the mailbox |
| Newsletter parser | Which newsletter parser to apply to matched mail |
| Mode | `Automatic` (push articles immediately) or `Manual review` (park for human approval) |
| IMAP host / Port / SSL | Connection to the mail server (default port 993 with SSL) |
| Folder | Mailbox folder to read (default `INBOX`) |
| Username / Password | Mailbox credentials (use an app password where the provider requires one) |
| Match subjects | Subject substrings, one per line; a match on any one selects the mail |
| Match senders | Sender substrings, one per line; matched against the From header and a forwarded message's original sender |
| Source reliability | Admiralty scale rating recorded for the source |

"Test connection" opens the mailbox with the entered settings without reading or changing any mail. Polling never deletes mail; processed messages are flagged with the `zsazsaProcessed` IMAP keyword so they are not handled twice.

### Manual sources pushing to scraper

Some manual sources do not store events directly but hand article links to the misp-scraper, which fetches and creates them.

| Field | Description |
|---|---|
| Redis host | Host of the misp-scraper Redis (`SCRAPER_REDIS_HOST`) |
| Port | Redis port (`SCRAPER_REDIS_PORT`) |
| Password | Redis password, if the instance requires one (`SCRAPER_REDIS_PASSWORD`) |
| Channel | Publish/subscribe channel the scraper subscribes to (`SCRAPER_REDIS_CHANNEL`, default `urls`) |

The scraper's own `subscribe` service must be running.
