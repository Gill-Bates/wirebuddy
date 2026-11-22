# Contributing

Thank you for considering contributing to WireBuddy! This guide will help you get started.

## Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity, experience level, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior:**

- ✅ Using welcoming and inclusive language
- ✅ Being respectful of differing viewpoints
- ✅ Gracefully accepting constructive criticism
- ✅ Focusing on what is best for the community

**Unacceptable behavior:**

- ❌ Trolling, insulting/derogatory comments, personal attacks
- ❌ Public or private harassment
- ❌ Publishing others' private information
- ❌ Other conduct which could reasonably be considered inappropriate

## How to Contribute

### Reporting Bugs

Found a bug? Please open an issue on GitHub:

**Before creating an issue:**

1. Check existing issues (open and closed)
2. Update to latest version and test again
3. Collect debug information

**Bug report should include:**

- **Title:** Short, descriptive summary
- **Description:** Detailed explanation of the issue
- **Steps to reproduce:** Clear steps to reproduce the bug
- **Expected behavior:** What should happen
- **Actual behavior:** What actually happens
- **Environment:**
  - WireBuddy version
  - Docker version
  - Host OS and version
  - Browser (if UI issue)
- **Logs:** Relevant log output (use \`\`\` code blocks)
- **Screenshots:** If applicable

**Example:**

````markdown
### Bug: DNS queries not being blocked

**Description:**
DNS ad-blocking is not working. All queries are allowed even with blocklists enabled.

**Steps to Reproduce:**
1. Enable DNS resolver
2. Enable StevenBlack blocklist
3. Restart DNS resolver
4. Query known ad domain: `nslookup ad.doubleclick.net 10.8.0.1`
5. Query is allowed instead of blocked

**Expected:** Query should be blocked
**Actual:** Query resolves to IP address

**Environment:**
- WireBuddy: 2.0.0
- Docker: 24.0.7
- Host OS: Ubuntu 22.04
- Browser: Chrome 120

**Logs:**
```
2026-03-15 14:30:00 UTC | DEBUG    | wirebuddy | DNS query from 10.8.0.2: ad.doubleclick.net A
2026-03-15 14:30:00 UTC | DEBUG    | wirebuddy | Blocklist check: not found in blocklist
```
````

### Requesting Features

Have an idea? Open a feature request:

**Feature request should include:**

- **Title:** Clear feature name
- **Problem:** What problem does this solve?
- **Solution:** Proposed solution
- **Alternatives:** Other solutions considered
- **Additional context:** Screenshots, mockups, examples

**Example:**

```markdown
### Feature: Two-Factor Authentication via SMS

**Problem:**
Some users don't have smartphones with authenticator apps and need SMS-based MFA.

**Proposed Solution:**
Add SMS as an MFA option alongside TOTP.

**Alternatives Considered:**
- Email-based codes (less secure)
- Hardware tokens only (expensive)

**Additional Context:**
- Could integrate with Twilio or similar
- Should be optional (admin configurable)
```

### Pull Requests

Ready to contribute code?

**Before starting:**

1. Check existing PRs (avoid duplicates)
2. Open an issue first (for large changes)
3. Fork the repository
4. Create a feature branch

**Development process:**

1. **Fork and clone:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/wirebuddy.git
   cd wirebuddy
   git remote add upstream https://github.com/Gill-Bates/wirebuddy.git
   ```

2. **Create branch:**
   ```bash
   git checkout -b feature/my-feature
   ```

3. **Make changes:**
   - Follow code style (see below)
   - Add tests for new features
   - Update documentation

4. **Test:**
   ```bash
   pytest
   ruff check .
   ruff format --check .
   ```

5. **Commit:**
   ```bash
   git add .
   git commit -m "feat: add SMS MFA support"
   ```
   
   Use [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation only
   - `style:` Formatting, missing semi-colons, etc.
   - `refactor:` Code change that neither fixes a bug nor adds a feature
   - `perf:` Performance improvement
   - `test:` Adding tests
   - `chore:` Updating build tasks, package manager configs, etc.

6. **Push:**
   ```bash
   git push origin feature/my-feature
   ```

7. **Create PR:**
   - Go to GitHub and create Pull Request
   - Describe the change and how you tested it
   - Link related issues

**Pull request checklist:**

- [ ] Code follows project style guidelines
- [ ] Tests added/updated (if applicable)
- [ ] Documentation added/updated (if applicable)
- [ ] All tests pass (`pytest`)
- [ ] No linting or formatting errors (`ruff check .`, `ruff format --check .`)
- [ ] Commits follow conventional commit format
- [ ] PR description is clear and complete

## Code Style

### Python

**Style guide:** enforced entirely by Ruff (formatter and linter; no Black,
isort, or mypy in this project). The codebase is tab-indented — see
`[tool.ruff.format]` in `pyproject.toml`.

**Run before committing:**

```bash
ruff format .
ruff check .
```

**Type hints:** Use `|` unions instead of
`typing.Optional`/`typing.Union`, builtin generics (`list[str]`, `dict[str, int]`)
instead of `typing.List`/`typing.Dict`.

```python
def create_peer(name: str, ip: str, interface: str) -> Peer:
	pass


# Nullable return
def get_user(user_id: int) -> User | None:
	pass


# Collections
def list_peers() -> list[Peer]:
	pass
```

**Docstrings:** Google style (configured via `[tool.ruff.lint.pydocstyle]`,
`convention = "google"`).

```python
def create_peer(name: str, ip: str) -> Peer:
	"""Create a new WireGuard peer.

	Args:
		name: Descriptive peer name
		ip: IP address in CIDR notation

	Returns:
		The created peer.

	Raises:
		ValueError: If IP is invalid
		PeerExistsError: If peer already exists
	"""
	pass
```

### JavaScript

**Style:**

- Use modern ES6+ syntax
- const/let (no var)
- Arrow functions preferred
- Semicolons required
- Indent with 4 spaces
- JSON API calls go through `api()` from `api.js`, which adds the CSRF header,
  handles `401`, and returns the `data` of the response envelope; use `fetch`
  directly only where `api()` does not fit, such as binary downloads

**Example:**

```javascript
const fetchPeers = async () => {
    try {
        return await api('GET', '/api/wireguard/peers');
    } catch (error) {
        console.error('Failed to fetch peers:', error);
        throw error;
    }
};
```

### HTML/CSS

- Indent with 4 spaces
- Bootstrap 5 classes preferred
- Put a rule in the lowest CSS layer that owns it and use the `var(--wb-*)` tokens
  (see [CSS](setup.md#css))
- Follow existing patterns

## Testing

The suite is flat (`tests/test_<area>.py`) and hermetic — no running server, no
network, no real WireGuard or Unbound. Use the shared `conn` fixture from
`tests/conftest.py` for a fresh in-memory database with the full schema, and
`tmp_path`/`monkeypatch` for everything else. Files carry the project header block
and are tab-indented like the application code.

```python
import pytest

from app.db.sqlite_users import LastAdminError, create_user, delete_user


def test_last_admin_cannot_be_deleted(conn):
	"""The DB layer refuses to remove the final administrator."""
	user_id = create_user(conn, "admin", "Correct-Horse-1", is_admin=True)
	with pytest.raises(LastAdminError):
		delete_user(conn, user_id)
```

Add a regression test alongside any security or persistence fix and name it after
the behaviour. `tests/AGENTS.md` maps each existing file to the area it covers.

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_peer_tags.py

# Specific test
pytest tests/test_peer_tags.py::test_enabled_adblocker_writes_peer_tags

# With coverage
pytest --cov=app --cov-report=html

# Verbose
pytest -v

# Stop on first failure
pytest -x
```

### Browser regression suite
`tests/layout/` is a Playwright suite that opens every page in a matrix of viewports and
themes against a real, throwaway WireBuddy instance (random credentials, temporary data
directory, no WireGuard interface or peer is created). It fails on page, console or CSP
errors, 429/5xx responses, unintended horizontal overflow and serious axe findings, and it
also covers navigation, the theme toggle, login and logout, and the modals.
Prerequisites: Node.js 24, the Python venv with the dev extras, then once:
```bash
npm ci
npx playwright install chromium webkit firefox
```
Run it from the repository root:
```bash
# PR profile: Chromium desktop and mobile, WebKit mobile cells
node tests/layout/run.mjs --profile quick --browsers chromium,webkit
# Full matrix: all viewports, both themes everywhere, Firefox too
node tests/layout/run.mjs --profile full --browsers chromium,webkit,firefox
# One page, one viewport; the audit self-test; list what a selection runs
node tests/layout/run.mjs --pages dashboard --viewports phone-390x844
node tests/layout/run.mjs --self-test
node tests/layout/run.mjs --browsers webkit -- --list
```
`WIREBUDDY_LAYOUT_WORKERS` sets the worker count (default at most 2). A failing run keeps
screenshots and traces in `WIREBUDDY_LAYOUT_OUTPUT` and the server logs in
`WIREBUDDY_LAYOUT_LOGS`; open a trace with `npx playwright show-trace <trace.zip>`.
To add a page or viewport, add one entry to `PAGES` or `VIEWPORTS` in
`tests/layout/harness.mjs`. Do not add fixed waits or raise timeouts to get a run green, and
give every allow-list entry a reason (`tests/layout/AGENTS.md` has the rules).

CI runs the suite as job `layout` of `ci.yml` on UI-relevant changes. The job needs the
`RELEASE_TOKEN` secret to install the private `gillbates-*` packages, which GitHub does not
hand to pull requests from forks, so the job cannot run for them; the workflow deliberately
does not use `pull_request_target`, because that would run untrusted code with the secret.
The job is currently non-blocking (see `.github/workflows/AGENTS.md`).

## Documentation

### Code Comments

```python
# Good: Explain why, not what
# Generate random token for CSRF protection (crypto-safe)
token = secrets.token_urlsafe(32)

# Bad: Obvious comment
# Create a token
token = secrets.token_urlsafe(32)
```

### Docstrings

All public functions, classes, and modules should have docstrings.

### Documentation Pages

When adding features, update relevant docs:

- `docs/features/` - Feature documentation
- `docs/api/` - API documentation
- `docs/configuration/` - Configuration guides
- `README.md` - Update if needed

## Git Workflow

### Branch Naming

- `feature/feature-name` - New features
- `fix/bug-description` - Bug fixes
- `docs/what-changed` - Documentation
- `refactor/what-changed` - Refactoring
- `test/what-tested` - Tests only

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Examples:**

```
feat(dns): add DNS-over-HTTPS support

Implement DoH in addition to DoT for upstream queries.
Includes configuration UI and Unbound integration.

Closes #123
```

```
fix(auth): prevent session fixation attack

Regenerate session ID after successful login to prevent
session fixation vulnerability.
```

### Keeping Fork Updated

```bash
# Add upstream remote (once)
git remote add upstream https://github.com/Gill-Bates/wirebuddy.git

# Fetch upstream changes
git fetch upstream

# Merge into main
git checkout main
git merge upstream/main

# Update feature branch
git checkout feature/my-feature
git rebase main
```

## Review Process

### PR Review

All PRs are reviewed by maintainers:

1. **Automated checks:** every job of `.github/workflows/ci.yml` (table below)
   must pass; a PR that touches the documentation or its toolchain also runs
   `.github/workflows/docs-build.yml` (build, link check, dependency scan)
2. **Code review:** Maintainer reviews code
3. **Feedback:** Maintainer may request changes
4. **Approval:** Once approved, PR is merged

| `ci.yml` job | Checks |
|--------------|--------|
| `manifest` | `pyproject.toml` is the only manifest, the version is release-shaped, tests of the `.github/scripts` helpers |
| `workflows` | actionlint and shellcheck of the workflows |
| `zizmor` | Workflow security lint |
| `container` | `bash -n` and shellcheck of `docker/entrypoint.sh` and `docker/healthcheck.sh`, `docker build --check -f docker/Dockerfile .` |
| `check` | `ruff check .`, `ruff format --check .`, `pytest` |
| `source-scan` | Trivy secret scan of the source tree |

### Addressing Feedback

```bash
# Make requested changes
git add .
git commit -m "refactor: address PR feedback"
git push
```

PR automatically updates.

## Release Process

(For maintainers)

1. Update the `version` field in `pyproject.toml` — this is the single source
   of truth; `app/utils/version.py` reads it back at runtime. The version is
   `X.Y.Z` with an optional `-suffix`; a suffixed version is a prerelease and
   never moves `latest`
2. Update `CHANGELOG.md`
3. Merge the release commit into `main`
4. Tag that commit `v<version>` (must match `pyproject.toml` exactly) and push
   the tag: `git push origin v<version>`
5. `docker-build.yml` validates tag/version/branch ancestry, runs the CI gate,
   builds, smoke-tests and Trivy-scans both architectures, checks that both
   were built with the same toolchain, pushes a candidate index, verifies it
   and only then promotes it to the version tag (and `latest` for the newest
   stable release)
6. The workflow then creates the GitHub release: a draft with the Trivy reports
   attached, published once name, size and SHA-256 of every report are
   verified. GitHub marks the release "Latest" only when Docker `latest` moved

Rerunning the release workflow for a tag republishes its version tag onto the
newly built image and updates the published GitHub release to match.

`security.yml` rescans the newest published stable image every week and opens
a tracking issue when the rescan fails.

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

See the [security policy](https://github.com/Gill-Bates/wirebuddy/blob/main/SECURITY.md)
for how to reach the maintainer privately.

A report helps most with:

- Vulnerability description
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Getting Help

- **GitHub Issues:** Questions, bugs, features
- **GitHub Discussions:** General discussion, ideas

## Recognition

Contributors are recognized in:

- GitHub contributors list
- `CHANGELOG.md` (for significant contributions)
- Special thanks in release notes

Thank you for contributing to WireBuddy! 🎉
