# Development Setup

Guide for setting up a local WireBuddy development environment.

## Prerequisites

### Required

- **Python 3.14+**
- **Git**
- **pip and venv**

### System Dependencies

=== "Ubuntu 26.04 / Debian testing"
    `python3.14` is packaged on Ubuntu 26.04 and Debian testing/unstable. On older
    releases (for example Debian 13 or Ubuntu 24.04), install
    [uv](https://docs.astral.sh/uv/getting-started/installation/) and run
    `uv python install 3.14`; it provides `python3.14` in `~/.local/bin`. Skip
    `python3.14` and `python3.14-venv` in the package list below, and create the
    virtual environment with `uv venv --python 3.14 .venv` instead of `python3.14 -m venv`.

    ```bash
    sudo apt update
    sudo apt install -y \
      python3.14 python3.14-venv python3-pip \
      wireguard-tools \
      unbound \
      conntrack \
      build-essential \
      libffi-dev \
      libssl-dev
    ```

=== "macOS"
    ```bash
    brew install python@3.14 wireguard-tools unbound
    ```

=== "Arch Linux"
    ```bash
    sudo pacman -S python python-pip wireguard-tools unbound conntrack-tools
    ```

## Clone Repository

```bash
git clone https://github.com/Gill-Bates/wirebuddy.git
cd wirebuddy
```

## Python Environment

### Create Virtual Environment

```bash
python3.14 -m venv .venv
source .venv/bin/activate
```

### Install Dependencies

`pyproject.toml` is the single manifest: it holds the release version, the runtime
dependencies, and the `dev` and `docs` extras.

Six runtime dependencies are `gillbates-*` packages from the private
`Gill-Bates/python-libraries` repository, pinned by git tag. Installing them needs git and
read access to that repository, for example through `gh auth setup-git`.

```bash
# Editable install with development dependencies (pytest, pytest-asyncio, pytest-cov, httpx2, questionary, ruff)
pip install -e ".[dev]"
```

## Configuration

### Create .env File

```bash
cp .env-example .env
```

### Edit .env

```bash
# Required: at least 32 bytes, e.g. the output of `head -c 32 /dev/urandom | base64`
WIREBUDDY_SECRET_KEY=<your-secret-key>

# Development settings
LOG_LEVEL=DEBUG
WIREBUDDY_DEV_RELOAD=true

# Database (dev). Both data/ and data_local/ are gitignored — keep the dev
# database inside one of them so encrypted keys never reach a commit.
WIREBUDDY_DATA_DIR=./data_local

# Optional bind overrides are available in Docker as WIREBUDDY_HOST and
# WIREBUDDY_PORT. A local `python -m app.server` reads host and port from the application DB.
```

### System Configuration

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Enable conntrack accounting
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

## Database Setup

WireBuddy automatically creates database on first run:

```bash
python -m app.server
```

This creates `data_local/wirebuddy.db` with the schema and a default `admin` user whose
one-time password is printed to the console. WireBuddy refuses to start when the data
directory or its `tsdb/` subdirectory is a symlink, or is group- or world-writable and
cannot be restricted to `0700`.

## Running WireBuddy

### Development Server

```bash
python -m app.server
```

Hot reload is enabled by exporting `WIREBUDDY_DEV_RELOAD=true` (a local start does not read `.env`; load it with `set -a; source .env; set +a`).

Access: `http://localhost:8000`

### Run Tests

```bash
pytest
```

### Run Linter

```bash
ruff check .
```

The full configured rule set gates every PR at zero findings; see
`pyproject.toml` for the `[tool.ruff.lint]` configuration and documented
exemptions.

### Format Code

```bash
ruff format .
```

Ruff is the only formatter and linter used in this project — there is no
Black, isort, mypy, or pylint dependency.

## IDE Setup

### VS Code

Install recommended extensions:

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "charliermarsh.ruff",
    "tamasfe.even-better-toml"
  ]
}
```

**Settings:**

```json
{
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.organizeImports": true
    }
  }
}
```

### PyCharm

1. Open project
2. Configure Python interpreter (point to `.venv/bin/python`)
3. Enable the Ruff plugin for linting and formatting

## Project Structure

```
wirebuddy/
├── app/                    # Application code
│   ├── __init__.py
│   ├── main.py            # create_app() factory and lifespan
│   ├── server.py          # Start path (HTTP or built-in HTTPS), also used by Docker
│   ├── api/               # FastAPI routers, split by resource
│   ├── db/                # sqlite_*.py data access, tsdb.py metrics store
│   ├── dns/               # Unbound config, blocklists, query-log ingestion
│   ├── node/              # Node-mode daemon, enrollment, metrics queue
│   ├── tasks/             # Scheduled background jobs
│   ├── middleware/        # CSRF middleware
│   ├── models/            # Pydantic models
│   ├── utils/             # Utilities (crypto, vault, geoip, conntrack, ...)
│   ├── static/            # CSS design system, vanilla JS
│   └── templates/         # Jinja2 templates
├── tests/                 # Flat pytest suite (test_*.py), e2e/ browser drivers
├── tools/                 # UI linter, Stylelint setup, CI helpers
├── docker/                # Dockerfile, entrypoint, compose files
├── docs/                  # Zensical documentation sources
├── data/                  # Runtime data (gitignored)
├── pyproject.toml         # Project metadata, version, dependencies, dev/docs extras
├── README.md
├── LICENSE
└── .gitignore
```

## Development Workflow

### Create Feature Branch

```bash
git checkout -b feature/my-feature
```

### Make Changes

1. Write code
2. Add tests
3. Run tests: `pytest`
4. Format code: `ruff format .`
5. Lint code: `ruff check .`

### Commit Changes

```bash
git add .
git commit -m "feat: add new feature"
```

Use conventional commits — see
[Commit Messages](contributing.md#commit-messages) for the type list and examples.

### Push and Create PR

```bash
git push origin feature/my-feature
```

Create Pull Request on GitHub.

## Debugging

### VS Code Debugger

`.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: FastAPI",
      "type": "python",
      "request": "launch",
      "module": "uvicorn",
      "args": [
        "app:create_app",
        "--factory",
        "--reload",
        "--host", "0.0.0.0",
        "--port", "8000"
      ],
      "jinja": true,
      "justMyCode": false
    }
  ]
}
```

### Python Debugger

Insert breakpoint:

```python
import pdb

pdb.set_trace()

# Or use the built-in
breakpoint()
```

### Logging

```python
import logging

logger = logging.getLogger(__name__)
logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message")
```

## Database Management

### SQLite CLI

```bash
sqlite3 data_local/wirebuddy.db

# Common commands
.schema               # Show schema
.tables               # List tables
SELECT * FROM users;  # Query
.quit                 # Exit
```

### Schema Changes

There is no Alembic or external migration tool. The baseline schema is created by
`init_schema()` in `app/db/sqlite_schema.py`, and version-to-version upgrades are
applied in `app/utils/migration.py` against the `schema_version` table.

## Testing

The pytest suite is flat — `tests/test_*.py`, no `unit`/`integration` split. Select
by file or by name:

```bash
pytest                                  # everything
pytest tests/test_login_lockout.py      # one file
pytest -k lockout                       # by name
pytest -x                               # stop on first failure
```

The browser-side formatting module `app/static/js/core/format.js` has Node tests in
`tests/js/`, outside pytest (Node 24 needs the quoted glob):

```bash
node --test "tests/js/*.test.mjs"
```

### Test Coverage

```bash
pytest --cov=app --cov-report=html
open htmlcov/index.html
```

### Fixtures

The suite is hermetic: no running server, no real WireGuard or Unbound, no
network. `tests/conftest.py` provides the one shared fixture, `conn`, a fresh
in-memory SQLite database with the full application schema:

```python
def test_last_admin_cannot_be_deleted(conn):
	user_id = create_user(conn, "admin", "Correct-Horse-1", is_admin=True)
	with pytest.raises(LastAdminError):
		delete_user(conn, user_id)
```

Use `tmp_path` for anything that needs files and `monkeypatch` for environment
and collaborators. See `tests/AGENTS.md` for the per-file map of what is covered.

## Frontend Development

### CSS

Located in `app/static/css/`. `base.html` loads the layers in this order, later
layers overriding earlier ones:

- `core/` (design tokens), `foundations/`, `components/`, `utilities/`
- `wb-ui-system.css` (central UI system) and `style.css` (app shell)
- per-page sheets from `pages/`, which import the page rule bodies
  (`dashboard.css`, `peers.css`, `traffic.css`, `dns.css`, `users.css`, `login.css`)

`status.css` is linked directly by the public status pages.

### JavaScript

Located in `app/static/js/` — vanilla JS, no build step. One script per page
(`dashboard.js`, `peers.js`, `traffic.js`, …) plus shared modules: `api.js` for
all backend calls, `core/` for primitives, and `components/` for reusable widgets.

### Templates

Jinja2 templates in `app/templates/`:

```jinja2
{% extends "base.html" %}

{% block title %}Dashboard{% endblock %}

{% block content %}
<h1>Dashboard</h1>
<!-- content -->
{% endblock %}
```

### Hot Reload

Templates auto-reload on save (development mode).

### UI Checks

The regression suite `tests/layout/` runs in CI (job `layout`) and locally with a repository-local
Playwright install; see "Browser regression suite" in the contributing guide. The exploratory drivers
below run only locally against an isolated throwaway instance. With Playwright installed under
`/opt/ux-test-tools`:

```bash
PLAYWRIGHT_DIR=/opt/ux-test-tools PYTHON=.venv/bin/python \
  node tests/e2e/live_resize.mjs "$(mktemp -d /tmp/wb-ux-e2e.XXXXXX)"
```

The other drivers are `ui_lint_isolated.mjs` (full `tools/ui-lint` audit) and
`ios_viewport_audit.mjs`; `PLAYWRIGHT_BROWSER` (`chromium`, `webkit`, `firefox`) and
`COLOR_SCHEME` select the engine and scheme. See `tests/e2e/AGENTS.md` and
`tools/ui-lint/AGENTS.md`. CSS lint is optional: `cd tools/stylelint && npm install && npm run lint`.

## Documentation

### Build Docs Locally

```bash
# Install only the docs toolchain (the "docs" extra in pyproject.toml)
pip install -r <(python3 tools/pyproject-deps.py docs)

# docs-build.yml publishes these two root files as documentation pages.
cp CHANGELOG.md docs/changelog.md
cp LICENSE docs/license.md

# Serve docs
zensical serve --config-file zensical.toml

# Open http://127.0.0.1:8000
```

### Add Documentation

1. Create markdown file in `docs/`
2. Add it to the `nav` in the root `zensical.toml`
3. Preview with `zensical serve --config-file zensical.toml`, then check it with `zensical build --config-file zensical.toml --strict --clean`
4. Commit changes

## Building Docker Image

### Local Build

The Dockerfile lives in `docker/` but its build context is the repository root:

The build reads the `gillbates-*` packages with a GitHub token for `Gill-Bates/python-libraries`,
passed as the BuildKit secret `python_libraries_token`; it stays out of the image layers:

```bash
export PYTHON_LIBRARIES_TOKEN="$(gh auth token)"  # or any token with read access
docker build --secret id=python_libraries_token,env=PYTHON_LIBRARIES_TOKEN \
  -t wirebuddy:dev -f docker/Dockerfile .
```

To reproduce the CI lint gate without a full build:

```bash
docker build --check -f docker/Dockerfile .
bash -n docker/entrypoint.sh
```

### Multi-Platform Build

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --secret id=python_libraries_token,env=PYTHON_LIBRARIES_TOKEN \
  -t wirebuddy:dev -f docker/Dockerfile .
```

### Run Local Image

```bash
docker run -d \
  --name wirebuddy-dev \
  --network host \
  --cap-add NET_ADMIN \
  -e WIREBUDDY_SECRET_KEY="<your-secret-key>" \
  -v $(pwd)/data:/app/data \
  wirebuddy:dev
```

## Troubleshooting

### Import Errors

```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Reinstall dependencies
pip install -e ".[dev]"
```

### Database Locked

```bash
# Close all connections
pkill -f wirebuddy

# Or delete database (dev only)
rm data_local/wirebuddy.db
```

### Port Already in Use

```bash
# Kill process on port 8000
lsof -ti:8000 | xargs kill -9
```

## Next Steps

- [Architecture](architecture.md) - System architecture
- [Contributing](contributing.md) - Contribution guidelines
- [API Documentation](../api/overview.md) - API reference
