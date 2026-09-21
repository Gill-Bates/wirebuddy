# Architecture

WireBuddy system architecture and design decisions.

## High-Level Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        A[Web Browser]
        B[WireGuard Client]
        C[API Client]
    end
    
    subgraph "Application Layer"
        D[FastAPI App]
        E[Uvicorn ASGI Server]
    end
    
    subgraph "Business Logic"
        F[Auth & Sessions]
        G[WireGuard Manager]
        H[DNS Resolver]
        I[Metrics Collector]
    end
    
    subgraph "Data Layer"
        J[SQLite Database]
        K[TSDB]
        L[File Storage]
    end
    
    subgraph "System Layer"
        M[WireGuard Kernel Module]
        N[Unbound DNS]
        O[Conntrack]
    end
    
    A --> D
    C --> D
    B --> M
    D --> E
    D --> F
    D --> G
    D --> H
    D --> I
    F --> J
    G --> J
    G --> M
    H --> N
    I --> K
    I --> O
    G --> L
```

## Multi-Node Architecture

WireBuddy supports deploying multiple WireGuard nodes across different geographic locations while maintaining centralized management. See [Multi-Node Deployment](../features/multi-node.md) for details.

```mermaid
graph TB
    subgraph "Master Server"
        M[WireBuddy Master]
        DB[(Database)]
        UI[Web UI]
    end
    
    subgraph "Node Servers"
        N1[Node 1<br/>Frankfurt]
        N2[Node 2<br/>New York]
        N3[Node 3<br/>Tokyo]
    end
    
    Admin[Admin] --> UI
    UI --> M
    M --> DB
    
    N1 -.Config Sync.-> M
    N2 -.Config Sync.-> M
    N3 -.Config Sync.-> M
    
    C1[Clients EU] --> N1
    C2[Clients US] --> N2
    C3[Clients Asia] --> N3
    
    style M fill:#4CAF50
    style N1 fill:#2196F3
    style N2 fill:#2196F3
    style N3 fill:#2196F3
```

**Key Components:**

- **Master**: Full application with web UI, API, and database
- **Nodes**: Lightweight WireGuard-only servers with sync daemon
- **Sync Protocol**: HTTPS with mutual certificate authentication
- **Config Distribution**: Pull-based model with version tracking

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Web Framework** | FastAPI | REST API and web interface |
| **ASGI Server** | Uvicorn | High-performance async server |
| **Database** | SQLite3 | Configuration and user data |
| **Time-Series DB** | Custom TSDB | Metrics storage |
| **Template Engine** | Jinja2 | HTML rendering |
| **VPN** | WireGuard | VPN server |
| **DNS** | Unbound | DNS resolver |
| **Frontend** | Bootstrap 5 | Responsive UI |
| **Charts** | Chart.js | Traffic visualization |
| **Icons** | Material Icons | Icon set |

## Application Structure

### FastAPI Application

```python
# app/main.py
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="WireBuddy")

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Template engine
templates = Jinja2Templates(directory="app/templates")

# Include routers
app.include_router(auth_api.router, prefix="/api")
app.include_router(wireguard_api.router, prefix="/api/wireguard")
# ...
```

### Router Pattern

```python
# app/api/wireguard.py
from fastapi import APIRouter, Depends
from app.models import PeerCreate, PeerResponse
from app.db import get_db

router = APIRouter()

@router.post("/peers", response_model=PeerResponse)
async def create_peer(
    peer: PeerCreate,
    db = Depends(get_db),
    user = Depends(get_current_user)
):
    # Validate
    # Create peer
    # Return response
    pass
```

## Database Schema

The baseline schema lives in `app/db/sqlite_schema.py` (`init_schema()`); this
section shows the core tables in abbreviated form. See that module for the
authoritative column list, constraints, and indexes.

### Users Table

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    must_change_password INTEGER NOT NULL DEFAULT 0,
    otp_secret TEXT,
    otp_enabled INTEGER NOT NULL DEFAULT 0,
    otp_recovery_codes TEXT,
    auth_method TEXT NOT NULL DEFAULT 'password',
    passkey_enabled INTEGER NOT NULL DEFAULT 0,
    last_login_at timestamp,
    last_login_ip TEXT,
    created_at timestamp NOT NULL
);
```

### Interfaces Table

```sql
CREATE TABLE interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    address TEXT NOT NULL,
    address6 TEXT,
    listen_port INTEGER NOT NULL DEFAULT 51820,
    client_endpoint_port INTEGER
    -- additional columns: see app/db/sqlite_schema.py
);
```

### Peers Table

```sql
CREATE TABLE peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key TEXT NOT NULL UNIQUE,
    private_key TEXT,
    preshared_key TEXT,
    name TEXT,
    allowed_ips TEXT NOT NULL,
    allowed_ips_mode TEXT NOT NULL DEFAULT 'full',
    peer_address TEXT,
    endpoint TEXT,
    interface TEXT NOT NULL DEFAULT 'wg0',
    is_enabled INTEGER NOT NULL DEFAULT 1,
    use_adblocker INTEGER NOT NULL DEFAULT 1,
    cumulative_rx INTEGER NOT NULL DEFAULT 0,
    cumulative_tx INTEGER NOT NULL DEFAULT 0,
    node_id TEXT REFERENCES nodes(id) ON DELETE SET NULL,
    created_at timestamp NOT NULL,
    updated_at timestamp NOT NULL
);
```

### Auth Tokens Table

Session tokens are stored hashed, never in plaintext:

```sql
CREATE TABLE auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at timestamp NOT NULL,      -- idle expiry (1 hour, refreshed on use)
    max_expires_at timestamp NOT NULL,  -- absolute expiry (24 hours)
    created_at timestamp NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

## Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant B as Browser
    participant API as FastAPI
    participant DB as Database
    
    U->>B: Enter credentials
    B->>API: POST /api/login
    API->>DB: Query user by username
    DB-->>API: User data + password hash
    API->>API: Verify password (PBKDF2)
    alt MFA Enabled
        API-->>B: Require MFA
        B->>U: Request TOTP code
        U->>B: Enter code
        B->>API: Send TOTP code
        API->>API: Verify TOTP
    end
    API->>API: Generate session token
    API->>DB: Store session (hashed)
    API-->>B: Set session cookie
    B-->>U: Logged in
```

## WireGuard Management

### Configuration Generation

```python
def generate_interface_config(interface: Interface) -> str:
    config = f"""[Interface]
PrivateKey = {interface.private_key}
Address = {interface.address}
ListenPort = {interface.listen_port}
"""
    
    # Add peers
    for peer in interface.peers:
        config += f"""
[Peer]
PublicKey = {peer.public_key}
AllowedIPs = {peer.allowed_ips}
"""
        if peer.preshared_key:
            config += f"PresharedKey = {peer.preshared_key}\n"
        if peer.persistent_keepalive:
            config += f"PersistentKeepalive = {peer.persistent_keepalive}\n"
    
    return config
```

### Interface Management

```python
class WireGuardManager:
    def start_interface(self, name: str):
        # Generate config
        config = self.generate_config(name)
        
        # Write to file
        config_path = f"/etc/wireguard/{name}.conf"
        with open(config_path, 'w') as f:
            f.write(config)
        
        # Start with wg-quick
        subprocess.run(["wg-quick", "up", name], check=True)
    
    def stop_interface(self, name: str):
        subprocess.run(["wg-quick", "down", name], check=True)
```

## DNS Integration

### Unbound Configuration

```python
def generate_unbound_config(settings: DNSSettings) -> str:
    config = """
server:
    verbosity: 1
    interface: 10.8.0.1
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    
    # Performance
    num-threads: 4
    msg-cache-size: 50m
    rrset-cache-size: 100m
    
    # Security
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
"""
    
    # Add blocklists
    for domain in settings.blocked_domains:
        config += f'    local-zone: "{domain}" always_refuse\n'
    
    # DoT upstream
    if settings.dot_enabled:
        config += """
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
"""
    
    return config
```

### Query Logging

```python
class DNSQueryLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.tailer = FileTailer(log_path)
    
    async def stream_queries(self):
        async for line in self.tailer:
            query = self.parse_query(line)
            yield query
    
    def parse_query(self, line: str) -> DNSQuery:
        # Parse Unbound log format
        # Return structured query object
        pass
```

WireBuddy uses dual storage for DNS telemetry:

- **JSONL files:** append-only raw query logs for the log UI, audits, and debugging
- **TSDB series:** write-time minute aggregates for trend charts and other read-heavy views
  - `queries_total` — integer counter per minute bucket
  - `queries_blocked` — integer counter per minute bucket

Separate counters (vs. pre-computed ratios) are more precise and flexible for UI aggregation.

This split keeps the ingestion path robust while making long-range trend queries cheap.

## Metrics Collection

### Conntrack Monitoring

```python
class ConntrackMonitor:
    def __init__(self):
        self.conntrack_path = "/proc/net/nf_conntrack"
    
    def collect_peer_traffic(self, peer_ip: str) -> dict:
        traffic = {"tx": 0, "rx": 0}
        
        with open(self.conntrack_path) as f:
            for line in f:
                # Parse conntrack entry
                if peer_ip in line:
                    entry = self.parse_entry(line)
                    traffic["tx"] += entry.bytes_orig
                    traffic["rx"] += entry.bytes_reply
        
        return traffic
```

### Time-Series Database

```python
class TSDB:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.init_schema()
    
    def record_metric(self, metric: str, value: float, tags: dict):
        timestamp = int(time.time())
        self.db.execute(
            "INSERT INTO metrics (timestamp, metric, value, tags) VALUES (?, ?, ?, ?)",
            (timestamp, metric, value, json.dumps(tags))
        )
        self.db.commit()
    
    def query(self, metric: str, start: int, end: int) -> list:
        cursor = self.db.execute(
            "SELECT timestamp, value FROM metrics WHERE metric = ? AND timestamp BETWEEN ? AND ?",
            (metric, start, end)
        )
        return cursor.fetchall()
```

## Security Architecture

### Password Hashing

```python
def hash_password(password: str) -> tuple[bytes, bytes]:
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000
    )
    key = kdf.derive(password.encode())
    return salt, key
```

### Secret Encryption

Implemented in `app/utils/vault.py`. Current writes use the "vault:2" scheme:
PBKDF2-HMAC-SHA256 derives a deployment master key from `WIREBUDDY_SECRET_KEY`
(default 480,000 iterations, tunable via `WIREBUDDY_PBKDF2_ITERATIONS`), then
HKDF-SHA256 plus a random per-row salt derives the row key that Fernet uses:

```python
def _derive_master_key_v2(pepper: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        pepper.encode("utf-8"),
        _MASTER_SALT_V2,
        iterations=_PBKDF2_ITERATIONS,  # default 480_000
    )
```

See [Security Overview](../security/overview.md#secrets-at-rest) for the full
model, including the legacy "vault:1" per-row PBKDF2 format still readable for
backward compatibility.

## Frontend Architecture

### JavaScript Structure

```javascript
// app/static/js/main.js
const WireBuddy = {
    init() {
        this.setupEventListeners();
        this.loadDashboard();
    },
    
    async loadPeers() {
        const response = await fetch('/api/wireguard/stats/peers-enriched');
        const data = await response.json();
        this.updatePeers(data.data);
    },
    
    updatePeers(peers) {
        document.getElementById('peer-count').textContent = peers.length;
        // ...
    }
};

document.addEventListener('DOMContentLoaded', () => WireBuddy.init());
```

### Chart Integration

```javascript
const TrafficChart = {
    chart: null,
    
    init(canvasId) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        this.chart = new Chart(ctx, {
            type: 'line',
            data: { /* ... */ },
            options: { /* ... */ }
        });
    },
    
    update(data) {
        this.chart.data.datasets[0].data = data;
        this.chart.update();
    }
};
```

## Deployment Architecture

### Docker Container

```dockerfile
FROM python:3.13-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wireguard-tools \
    unbound \
    conntrack \
    && rm -rf /var/lib/apt/lists/*

# Copy application
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY . .

# Non-root user
RUN useradd -m wirebuddy
USER wirebuddy

# Start application
CMD ["uvicorn", "app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose

```yaml
services:
  wirebuddy:
    image: giiibates/wirebuddy:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
    volumes:
      - ./data:/app/data
    environment:
      WIREBUDDY_SECRET_KEY: "${WIREBUDDY_SECRET_KEY:?Set WIREBUDDY_SECRET_KEY in .env}"
```

## Performance Considerations

### Database Optimization

- SQLite WAL mode for concurrent reads
- Indexes on frequently queried columns
- Connection pooling (AsyncIO)

### Caching

- DNS query cache (Unbound)
- Session cache (in-memory)
- Metrics cache (Redis in future)

### Async Operations

- FastAPI async handlers
- Async database queries (aiosqlite)
- Background tasks (BackgroundTasks)

## Scalability

### Current Limitations

- Single-server deployment
- SQLite (not distributed)
- No horizontal scaling

### Future Enhancements

- PostgreSQL support
- Redis for caching
- Distributed mode (multiple workers)
- Metrics persistence (InfluxDB, Prometheus)

## Monitoring & Observability

### Logging

- Structured logging (JSON)
- Log levels (DEBUG, INFO, WARNING, ERROR)
- Audit logs (security events)

### Metrics (Future)

- Prometheus exporter
- Grafana dashboards
- Custom alerts

## Design Decisions

### Why SQLite?

✅ **Pros:**
- Simple deployment (no separate DB server)
- Fast for single-server workload
- Embedded, no maintenance
- ACID compliant

❌ **Cons:**
- No network access (must be local)
- Limited concurrent writes
- No replication

### Why FastAPI?

✅ **Pros:**
- Modern async framework
- Automatic OpenAPI docs
- Type hints and validation
- High performance

### Why Unbound?

✅ **Pros:**
- Lightweight and fast
- DNSSEC support
- Easy configuration
- Well-tested and secure

## Next Steps

- [Development Setup](setup.md) - Local development
- [Contributing](contributing.md) - Contribution guidelines
