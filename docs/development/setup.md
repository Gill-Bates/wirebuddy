# Development Setup

Guide for setting up a local WireBuddy development environment.

## Prerequisites

### Required

- **Python 3.13+**
- **Git**
- **pip and venv**

### System Dependencies

=== "Ubuntu/Debian"
    ```bash
    sudo apt update
    sudo apt install -y \
      python3.13 python3.13-venv python3-pip \
      wireguard-tools \
      unbound \
      conntrack \
      build-essential \
      libffi-dev \
      libssl-dev
    ```

=== "macOS"
    ```bash
    brew install python@3.13 wireguard-tools unbound
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
python3.13 -m venv .venv
source .venv/bin/activate
```

### Install Dependencies

`pyproject.toml` is the single manifest: it holds the release version, the runtime
dependencies, and the `dev` and `docs` extras.

```bash
# Editable install with development dependencies (pytest, ruff)
pip install -e ".[dev]"
```

## Configuration

### Create .env File

```bash
cp .env-example .env
```

### Edit .env

```bash
# Required
WIREBUDDY_SECRET_KEY=dev-secret-key-change-me

# Development settings
LOG_LEVEL=DEBUG
WIREBUDDY_DEV_RELOAD=true

# Database (dev)
WIREBUDDY_DATA_DIR=./dev-data

# Optional bind overrides are available in Docker as WIREBUDDY_HOST and
# WIREBUDDY_PORT. Local run.py reads host and port from the application DB.
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
python run.py
```

This creates `dev-data/wirebuddy.db` with schema and default admin user.

## Running WireBuddy

### Development Server

```bash
python run.py
```

Hot reload is enabled by `WIREBUDDY_DEV_RELOAD=true` in `.env`.

Access: `http://localhost:8000`

### Run Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=app --cov-report=html
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
│   ├── main.py            # FastAPI app entry point
│   ├── api/               # API endpoints
│   │   ├── auth.py
│   │   ├── wireguard.py
│   │   └── ...
│   ├── db/                # Database modules
│   │   ├── sqlite_*.py
│   │   └── ...
│   ├── dns/               # DNS resolver
│   ├── models/            # Pydantic models
│   ├── utils/             # Utilities
│   ├── static/            # CSS, JS, images
│   └── templates/         # Jinja2 templates
├── tests/                 # Test suite
│   ├── test_api.py
│   ├── test_auth.py
│   └── ...
├── docs/                  # MkDocs documentation
├── data/                  # Runtime data (gitignored)
├── dev-data/              # Development data (gitignored)
├── pyproject.toml         # Project metadata, version, dependencies, dev/docs extras
├── run.py                 # Development entry point
├── setup.conf            # Configuration
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

Use conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `style:` Formatting
- `refactor:` Code restructuring
- `test:` Tests
- `chore:` Maintenance

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
import pdb; pdb.set_trace()

# Or use breakpoint() (Python 3.7+)
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
sqlite3 dev-data/wirebuddy.db

# Common commands
.schema               # Show schema
.tables               # List tables
SELECT * FROM users;  # Query
.quit                 # Exit
```

### Database Migrations

(If implementing Alembic in future)

```bash
# Create migration
alembic revision --autogenerate -m "Add new field"

# Apply migration
alembic upgrade head

# Rollback
alembic downgrade -1
```

## Testing

### Unit Tests

```bash
pytest tests/unit/
```

### Integration Tests

```bash
pytest tests/integration/
```

### End-to-End Tests

```bash
pytest tests/e2e/
```

### Test Coverage

```bash
pytest --cov=app --cov-report=html
open htmlcov/index.html
```

### Fixtures

```python
import pytest
from app.main import app
from fastapi.testclient import TestClient

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def admin_user(client):
    # Create and return admin user
    pass

def test_login(client, admin_user):
    response = client.post("/api/login", json={
        "username": "admin",
        "password": "admin"
    })
    assert response.status_code == 200
```

## Frontend Development

### CSS

Located in `app/static/css/`:

- `wb-ui-system.css` - Design system tokens
- `custom.css` - Custom styles

### JavaScript

Located in `app/static/js/`:

- `main.js` - Main application logic
- `charts.js` - Chart.js integration

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

## Documentation

### Build Docs Locally

```bash
# Install docs dependencies (the "docs" extra in pyproject.toml)
pip install -e ".[docs]"

# The CI workflow publishes these two root files as documentation pages.
cp CHANGELOG.md docs/changelog.md
cp LICENSE docs/license.md

# Serve docs
mkdocs serve -f docs/mkdocs.yml

# Open http://127.0.0.1:8000
```

### Add Documentation

1. Create markdown file in `docs/`
2. Add to `docs/mkdocs.yml` navigation
3. Preview with `mkdocs serve -f docs/mkdocs.yml`
4. Commit changes

## Building Docker Image

### Local Build

```bash
docker build -t wirebuddy:dev .
```

### Multi-Platform Build

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t wirebuddy:dev .
```

### Run Local Image

```bash
docker run -d \
  --name wirebuddy-dev \
  --network host \
  --cap-add NET_ADMIN \
  -e WIREBUDDY_SECRET_KEY=dev-key \
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
rm dev-data/wirebuddy.db
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
