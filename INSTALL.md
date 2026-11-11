# Installing zsazsa

<p align="center">
  <a href="https://zsazsa-project.org/documentation.html#install"><img alt="Quickstart: install" src="https://img.shields.io/badge/Quickstart-Install-0066cc?style=for-the-badge&logo=rocket&logoColor=white"></a>
</p>

This guide installs zsazsa, with Docker or next to MISP, and serves it under MISP's own address. The [quickstart](https://zsazsa-project.org/documentation.html) is the short path through the same steps. Once zsazsa runs, [Configuration](README.md#configuration) in the README describes every setting, and the rest of the [README](README.md) what zsazsa does.

## What you need

zsazsa sits on top of MISP and needs:

- **A MISP server**. zsazsa stores its stakeholders, requirements and products in MISP, this is `MISP_WEBAPP_URL`.
- **A MISP server with misp-scraper (optional).** The scraper turns articles into MISP events, which zsazsa reads for data collection and the analyser. This is `MISP_URL`, and it can be the same server. To run without one, leave `MISP_URL` and `MISP_KEY` empty or set `MISP_SCRAPER_ENABLED = False`. Collection then comes from other MISP servers and manual sources.
- **Other MISP servers (optional).** zsazsa can read events from community or partner servers, set up under Collection sources.

zsazsa does not install MISP or misp-scraper, so install those first. The Docker setup can run misp-scraper for you from its own checkout.

### Redis

zsazsa uses Redis for three things:

| Use | Settings | Needed for |
|---|---|---|
| MISP's session store | `MISP_SESSION_REDIS_*` (`config/__init__.py` only) | Single sign-on, which reads the logged-in MISP user from MISP's session. PHP must keep MISP's sessions in Redis (`session.save_handler = redis`) |
| Background jobs | `JOB_REDIS_*` (`config/__init__.py` only) | The state of running jobs |
| misp-scraper queue | `SCRAPER_REDIS_*` (Settings) | Sending newsletter articles to the scraper |

All three default to `127.0.0.1:6379`, database `0`, no password, so the Redis MISP already uses is usually enough. The Docker setup asks for MISP's Redis once and sets all three.

## Docker or a standard installation

**Docker** is the quickest way. `docker/setup.sh` asks how MISP, its Redis and misp-scraper run on the host, then builds and starts the web app, the analyser and the IMAP collector, each in its own container, and optionally misp-scraper. It can add the `/zsazsa` proxy to MISP's Apache, or to misp-core's nginx in misp-docker. Your configuration and data stay in `docker/volumes/`.

The **standard installation** runs zsazsa from a Python virtual environment in MISP's custom directory, as MISP's web user. You add the proxy to Apache, the service to systemd and the analyser and IMAP collector to cron yourself.

Both end in the same place: zsazsa under MISP's address, such as `https://misp.example.com/zsazsa`, configured with the setup wizard.

## Installing with Docker

You need Docker with the compose plugin (`docker compose version` should answer). Then:

```bash
git clone https://github.com/zsazsa-project/zsazsa.git
cd zsazsa
bash docker/setup.sh
```

The script asks its questions first and changes nothing until you answer yes to "Go ahead?". When it is done, go on with [Configuring zsazsa](#configuring-zsazsa). [docker/README.md](docker/README.md) explains what the setup changes, where your files are, the everyday commands and what to check when something does not work.

## Standard installation

### System packages

zsazsa needs **Python 3.11** or later, with `venv` and `pip`.

On Debian or Ubuntu:

```bash
sudo apt-get install python3-venv python3-pip python3-dev git \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev shared-mime-info
```

`python3-venv` is tied to a Python version, such as `python3.11-venv`. If the command cannot find it, install the one matching `python3 --version`.

On Fedora, RHEL or CentOS the packages are `python3-devel`, `cairo`, `pango`, `gdk-pixbuf2`, `libffi-devel` and `shared-mime-info`.

### Installing

Install zsazsa in MISP's custom directory and run it as MISP's web user, `www-data` on Ubuntu:

```bash
sudo mkdir -p /var/www/MISP/misp-custom
sudo chown www-data:www-data /var/www/MISP/misp-custom
cd /var/www/MISP/misp-custom
sudo -u www-data git clone https://github.com/zsazsa-project/zsazsa.git zsazsa
cd zsazsa
sudo -u www-data bash docs/install.sh
```

The installer checks the Python version, creates `venv`, installs `requirements.txt` and creates `data/`. When there is no `config/__init__.py` yet, it copies `config/__init__.py.example` and gives it a new `SECRET_KEY`. An existing config is left alone, so it is safe to run again. If an older Python is the default, name a newer one with `PYTHON=python3.11`.

The installer ends by offering a self-signed TLS certificate. Answer no unless zsazsa's own server will serve HTTPS directly: behind Apache, Apache handles TLS. To create the certificate later:

```bash
bash docs/create_cert.sh zsazsa.example.com
```

It writes `certs/zsazsa.crt` and `certs/zsazsa.key`, where `SSL_CERT` and `SSL_KEY` point by default, and never overwrites either. Without a hostname it uses this host's name. Set `SSL_ENABLED = True` to use it.

### The MISP connection

`config/__init__.py` has every setting, in the layout the Settings page writes. Set at least `MISP_WEBAPP_URL` and `MISP_WEBAPP_KEY`, and `MISP_URL` and `MISP_KEY` for a misp-scraper (or `MISP_SCRAPER_ENABLED = False` without one):

```python
MISP_WEBAPP_URL = 'https://misp.example.com'
MISP_WEBAPP_KEY = '<API key>'
MISP_WEBAPP_VERIFYCERT = True
```

For a MISP certificate from your own CA, see [Connections](README.md#connections) rather than turning verification off. If you use single sign-on, set `MISP_SESSION_REDIS_*` here too, as the interface does not change them. A MISP site admin can do everything else from the web interface.

### Running zsazsa

```bash
source venv/bin/activate
python run_webapp.py
```

zsazsa listens on `http://0.0.0.0:5000`, or `https://` with `SSL_ENABLED` on. `ZSAZSA_BIND` in the environment changes the address and `ZSAZSA_PORT` replaces `PORT`. `PORT` and `HOSTNAME` are on the System tab of the Settings page; restart zsazsa after changing the port. `HOSTNAME` only builds links and does not change the listener.

Run the analyser and the IMAP collector from the web user's crontab:

```bash
15 * * * * cd /var/www/MISP/misp-custom/zsazsa && venv/bin/python run_analyser.py
*/15 * * * * cd /var/www/MISP/misp-custom/zsazsa && venv/bin/python run_imap_collector.py
```

## Serving zsazsa under MISP's address

zsazsa runs under a subpath of MISP's Apache virtual host, such as `https://misp.example.com/zsazsa`. Any subpath works, `/cti` as well as `/zsazsa`, without a change to zsazsa.

Sharing MISP's address is also what makes single sign-on possible: the browser only sends MISP's session cookie to zsazsa on the same host.

The Docker setup offers to add the proxy for you. The steps below are for the standard installation, and for a MISP on another host than zsazsa.

### 1. Systemd

Copy the service template and adjust the paths and user:

```bash
sudo cp docs/zsazsa.service.template /etc/systemd/system/zsazsa.service
# edit the file, then:
sudo systemctl daemon-reload
sudo systemctl enable --now zsazsa.service
```

In production, uncomment `Environment=ZSAZSA_BIND=127.0.0.1` so zsazsa is only reachable through Apache. Leave it commented out only when other machines need to reach it directly, during development.

Behind an outbound proxy, set `https_proxy` and `no_proxy` in `/etc/environment`, which the service reads. Put your MISP servers and the other internal hosts zsazsa calls, such as a local LLM, in `no_proxy`. Docker containers do not read that file; [docker/README.md](docker/README.md) says how to give them the proxy.

### 2. Apache modules

```bash
sudo a2enmod proxy proxy_http headers
sudo systemctl reload apache2
```

### 3. The proxy in MISP's virtual host

Inside the existing `<VirtualHost *:443>` block of MISP's Apache configuration, add:

```apache
# zsazsa CTI application
ProxyPreserveHost On
RequestHeader set X-Forwarded-Prefix "/zsazsa"
RequestHeader set X-Forwarded-Proto "https"

ProxyPass        /zsazsa  http://127.0.0.1:5000/ timeout=300
ProxyPassReverse /zsazsa  http://127.0.0.1:5000/
```

`X-Forwarded-Prefix` must match the path in `ProxyPass` and `ProxyPassReverse`, so a different subpath changes all three. That only takes an Apache reload (`systemctl reload apache2`), not a zsazsa restart. zsazsa builds its links from `X-Forwarded-Prefix`, and the `https://` links in notifications and previews from `X-Forwarded-Proto`. Without a proxy, neither header is there and zsazsa serves from the root.

A MISP behind nginx needs the same three things: the prefix stripped from the path, `X-Forwarded-Prefix` and `X-Forwarded-Proto`. [docker/misp-docker/zsazsa-nginx.sh](docker/misp-docker/zsazsa-nginx.sh) has the `location` block the Docker setup adds to misp-core.

### 4. Single sign-on

With zsazsa under MISP's address, switch on **Require a MISP session** in the Single sign-on card of Settings > Configuration > System, save, and check it with **Test single sign-on**. PHP must keep MISP's sessions in Redis. [Single sign-on against MISP](README.md#single-sign-on-against-misp) in the README explains the requirements and the permissions zsazsa takes from MISP.

## Configuring zsazsa

Open zsazsa as a MISP site admin. The setup wizard, under Settings or at `/config/setup`, walks you through the rest: the organisation, the data collection sources, AI, the focus points and notifications. It saves to the same settings as the Settings page and can be run again at any time. The dashboard points to it until zsazsa has a data collection source and focus points.

Everything the wizard does not cover is on Settings > Configuration and Settings > Collection sources, and described in [Configuration](README.md#configuration) in the README.

## Upgrading

Read [CHANGELOG.md](CHANGELOG.md) first: a release can come with a migration you need to run.

With Docker, from the zsazsa folder:

```bash
git pull
cd docker
docker compose build --pull
docker compose up -d
```

`--pull` fetches the latest Python base image, with its security updates.

For a standard installation, pull as the web user and restart the service:

```bash
cd /var/www/MISP/misp-custom/zsazsa
sudo -u www-data git pull
sudo -u www-data venv/bin/pip install -r requirements.txt
sudo systemctl restart zsazsa.service
```

Then open Settings > Configuration > System and run every migration listed there that you have not run before. Each runs as a dry run first and is safe to run twice. Upgrading from a release before 1.0.0 needs **Align requirement scope and scope items**: before it, a technology, vendor, incident or campaign was written to only one of the two places a requirement keeps its scope, so it was either missing from the detail page or matched nothing.

## Optional: the ATT&CK technique list

The MITRE ATT&CK techniques offered in product forms and briefing stories are read from `data/mitre-attack-pattern.json`. Without that file, zsazsa queries the galaxy on your MISP instead. To create or refresh the file from the misp-galaxy repository on GitHub:

```bash
venv/bin/python scripts/fetch_mitre_galaxy.py
# or, in Docker, from the docker folder:
docker compose exec webapp python scripts/fetch_mitre_galaxy.py
```

Run it again now and then for new techniques. zsazsa picks up the new file without a restart.
