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

```markdown
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
- WireBuddy: 1.3.2
- Docker: 24.0.7
- Host OS: Ubuntu 22.04
- Browser: Chrome 120

**Logs:**
```
[2026-03-15 14:30:00] DEBUG: DNS query from 10.8.0.2: ad.doubleclick.net A
[2026-03-15 14:30:00] DEBUG: Blocklist check: not found in blocklist
```
```

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
   mypy app/
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
   - Fill in PR template
   - Link related issues

**Pull request checklist:**

- [ ] Code follows project style guidelines
- [ ] Tests added/updated (if applicable)
- [ ] Documentation added/updated (if applicable)
- [ ] All tests pass (`pytest`)
- [ ] No linting errors (`ruff check .`)
- [ ] Type checking passes (`mypy app/`)
- [ ] Commits follow conventional commit format
- [ ] PR description is clear and complete

## Code Style

### Python

**Style guide:** PEP 8 (enforced by Black and Ruff)

**Tools:**

- **Formatter:** Black
- **Linter:** Ruff
- **Type checker:** mypy

**Run before committing:**

```bash
black app/
isort app/
ruff check app/
mypy app/
```

**Type hints:**

```python
def create_peer(name: str, ip: str, interface: str) -> Peer:
    pass

# Use Optional for nullable
from typing import Optional
def get_user(user_id: int) -> Optional[User]:
    pass

# Use List, Dict for collections
from typing import List, Dict
def list_peers() -> List[Peer]:
    pass
```

**Docstrings:**

```python
def create_peer(name: str, ip: str) -> Peer:
    """
    Create a new WireGuard peer.
    
    Args:
        name: Descriptive peer name
        ip: IP address in CIDR notation
    
    Returns:
        Peer: Created peer object
    
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

**Example:**

```javascript
const fetchPeers = async () => {
    try {
        const response = await fetch('/api/wireguard/peers');
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Failed to fetch peers:', error);
        throw error;
    }
};
```

### HTML/CSS

- Indent with 2 spaces
- Bootstrap 5 classes preferred
- Custom CSS in `wb-ui-system.css`
- Follow existing patterns

## Testing

### Writing Tests

```python
import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def admin_token(client):
    """Get admin API token."""
    response = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "admin"
    })
    return response.json()["token"]

def test_create_peer(client, admin_token):
    """Test peer creation."""
    response = client.post(
        "/api/wireguard/peers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Test Peer",
            "interface": "wg0",
            "allowed_ips": "0.0.0.0/0, ::/0",
            "allowed_ips_mode": "full"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["data"]["name"] == "Test Peer"
    assert data["data"]["interface"] == "wg0"

def test_create_peer_duplicate(client, admin_token):
    """Test duplicate peer creation fails."""
    # Create first peer
    client.post("/api/wireguard/peers", headers={"Authorization": f"Bearer {admin_token}"}, json={...})
    
    # Attempt duplicate
    response = client.post("/api/wireguard/peers", headers={"Authorization": f"Bearer {admin_token}"}, json={...})
    assert response.status_code == 409
```

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_api.py

# Specific test
pytest tests/test_api.py::test_create_peer

# With coverage
pytest --cov=app --cov-report=html

# Verbose
pytest -v

# Stop on first failure
pytest -x
```

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

1. **Automated checks:** Tests, linting, type checking
2. **Code review:** Maintainer reviews code
3. **Feedback:** Maintainer may request changes
4. **Approval:** Once approved, PR is merged

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

1. Update `VERSION` file
2. Update `CHANGELOG.md`
3. Create git tag: `git tag v1.3.3`
4. Push tag: `git push --tags`
5. GitHub Actions builds and publishes Docker image
6. Create GitHub release with notes

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Email: [security contact - update as needed]

Include:

- Vulnerability description
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Getting Help

- **GitHub Issues:** Questions, bugs, features
- **GitHub Discussions:** General discussion, ideas
- **Discord:** (if/when created) Real-time chat

## Recognition

Contributors are recognized in:

- GitHub contributors list
- `CHANGELOG.md` (for significant contributions)
- Special thanks in release notes

Thank you for contributing to WireBuddy! 🎉
