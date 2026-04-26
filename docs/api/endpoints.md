# API Endpoints

Authoritative route list generated from mounted FastAPI routers.

- Generated: 2026-04-26 13:42:50Z
- Total endpoints: 128

## Authentication Model

- UI/API session: auth token cookie (`auth_token`)
- Programmatic API: `Authorization: Bearer <auth_token>`
- Node sync endpoints: node secret in Bearer header plus `X-Client-Cert-Fingerprint`

## Endpoints by Resource

### Auth

| Method | Path |
|---|---|
| POST | `/api/login` |
| POST | `/api/logout` |
| GET | `/api/me` |
| POST | `/api/me/otp/confirm` |
| POST | `/api/me/otp/recovery-codes/zip` |
| GET | `/api/me/otp/setup` |
| POST | `/api/mfa/verify` |

### Users

| Method | Path |
|---|---|
| GET | `/api/users` |
| POST | `/api/users` |
| DELETE | `/api/users/{user_id}` |
| GET | `/api/users/{user_id}` |
| PATCH | `/api/users/{user_id}` |
| POST | `/api/users/{user_id}/change-password` |
| POST | `/api/users/{user_id}/otp/confirm` |
| POST | `/api/users/{user_id}/otp/disable` |
| POST | `/api/users/{user_id}/otp/enable` |
| POST | `/api/users/{user_id}/reset-password` |

### Passkeys

| Method | Path |
|---|---|
| GET | `/api/passkeys` |
| GET | `/api/passkeys/available` |
| GET | `/api/passkeys/check` |
| POST | `/api/passkeys/disable/{user_id}` |
| POST | `/api/passkeys/enable/{user_id}` |
| POST | `/api/passkeys/login/finish` |
| POST | `/api/passkeys/login/start` |
| POST | `/api/passkeys/register/finish` |
| POST | `/api/passkeys/register/start` |
| POST | `/api/passkeys/reset/{user_id}` |
| GET | `/api/passkeys/user/{user_id}` |
| DELETE | `/api/passkeys/{passkey_id}` |

### Wireguard

| Method | Path |
|---|---|
| GET | `/api/wireguard/interfaces` |
| POST | `/api/wireguard/interfaces` |
| GET | `/api/wireguard/interfaces/_next-subnet` |
| GET | `/api/wireguard/interfaces/next-subnet` |
| DELETE | `/api/wireguard/interfaces/{name}` |
| GET | `/api/wireguard/interfaces/{name}` |
| PATCH | `/api/wireguard/interfaces/{name}` |
| GET | `/api/wireguard/interfaces/{name}/config` |
| POST | `/api/wireguard/interfaces/{name}/down` |
| POST | `/api/wireguard/interfaces/{name}/restart` |
| POST | `/api/wireguard/interfaces/{name}/up` |
| GET | `/api/wireguard/peers` |
| POST | `/api/wireguard/peers` |
| DELETE | `/api/wireguard/peers/{peer_id}` |
| GET | `/api/wireguard/peers/{peer_id}` |
| PATCH | `/api/wireguard/peers/{peer_id}` |
| GET | `/api/wireguard/peers/{peer_id}/config` |
| GET | `/api/wireguard/peers/{peer_id}/qrcode` |
| GET | `/api/wireguard/peers/{peer_id}/stats` |
| GET | `/api/wireguard/settings` |
| PATCH | `/api/wireguard/settings` |
| GET | `/api/wireguard/settings/check-updates` |
| POST | `/api/wireguard/settings/generate-psk` |
| GET | `/api/wireguard/settings/psk` |
| PUT | `/api/wireguard/settings/psk` |
| GET | `/api/wireguard/settings/traffic` |
| GET | `/api/wireguard/speedtest/history` |
| GET | `/api/wireguard/speedtest/nodes` |
| POST | `/api/wireguard/speedtest/run` |
| GET | `/api/wireguard/speedtest/run/stream` |
| GET | `/api/wireguard/speedtest/settings` |
| PATCH | `/api/wireguard/speedtest/settings` |
| DELETE | `/api/wireguard/speedtest/storage` |
| GET | `/api/wireguard/speedtest/storage` |
| PATCH | `/api/wireguard/speedtest/storage/retention` |
| GET | `/api/wireguard/stats/connections` |
| GET | `/api/wireguard/stats/peer-locations` |
| DELETE | `/api/wireguard/stats/peer-logs` |
| GET | `/api/wireguard/stats/peer-metrics` |
| GET | `/api/wireguard/stats/peers-enriched` |
| GET | `/api/wireguard/stats/traffic` |
| GET | `/api/wireguard/stats/traffic-by-asn` |
| GET | `/api/wireguard/stats/traffic-by-country` |
| DELETE | `/api/wireguard/stats/tsdb` |
| GET | `/api/wireguard/stats/tsdb` |
| POST | `/api/wireguard/stats/tsdb/maintenance` |
| PATCH | `/api/wireguard/stats/tsdb/retention` |

### Dns

| Method | Path |
|---|---|
| POST | `/api/dns/adblocker/mode` |
| GET | `/api/dns/adblocker/status` |
| GET | `/api/dns/blocklist/count` |
| GET | `/api/dns/blocklist/sources` |
| POST | `/api/dns/blocklist/sources` |
| POST | `/api/dns/blocklist/update` |
| GET | `/api/dns/config` |
| POST | `/api/dns/config` |
| GET | `/api/dns/custom-rules` |
| PATCH | `/api/dns/custom-rules` |
| POST | `/api/dns/custom-rules/actions` |
| DELETE | `/api/dns/logs` |
| GET | `/api/dns/logs` |
| POST | `/api/dns/restart` |
| GET | `/api/dns/selftest` |
| POST | `/api/dns/start` |
| GET | `/api/dns/status` |
| POST | `/api/dns/stop` |
| GET | `/api/dns/storage` |
| POST | `/api/dns/test-upstream` |
| GET | `/api/dns/top-domains` |
| GET | `/api/dns/trend` |

### Backup

| Method | Path |
|---|---|
| POST | `/api/backup/download` |
| GET | `/api/backup/list` |
| POST | `/api/backup/restore` |
| DELETE | `/api/backup/scheduled/{filename}` |
| GET | `/api/backup/settings` |
| PATCH | `/api/backup/settings` |
| POST | `/api/backup/validate` |

### Acme

| Method | Path |
|---|---|
| GET | `/api/acme/certificates` |
| GET | `/api/acme/certificates/challenge/{token}` |
| GET | `/api/acme/certificates/renewal-check` |
| POST | `/api/acme/certificates/request` |
| DELETE | `/api/acme/certificates/{domain}` |

### Nodes

| Method | Path |
|---|---|
| GET | `/api/nodes` |
| POST | `/api/nodes` |
| GET | `/api/nodes/config` |
| POST | `/api/nodes/enroll` |
| GET | `/api/nodes/events` |
| POST | `/api/nodes/heartbeat` |
| POST | `/api/nodes/speedtest` |
| POST | `/api/nodes/speedtest/progress` |
| DELETE | `/api/nodes/{node_id}` |
| GET | `/api/nodes/{node_id}` |
| PATCH | `/api/nodes/{node_id}` |
| POST | `/api/nodes/{node_id}/restart` |
| POST | `/api/nodes/{node_id}/speedtest` |
| GET | `/api/nodes/{node_id}/speedtest/stream` |
| POST | `/api/nodes/{node_id}/token` |

### Network

| Method | Path |
|---|---|
| GET | `/api/network/stats` |
| GET | `/api/network/stats/history` |

### System

| Method | Path |
|---|---|
| GET | `/api/system/status` |

## Notes

- This page reflects mounted routes at runtime (`create_app()`), including all included routers.
- Endpoint permissions vary (`get_current_user` vs `require_admin` vs node-specific auth dependencies).
- For request/response schemas, use the OpenAPI spec at `/openapi.json` and Swagger UI at `/docs`.
