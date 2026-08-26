---
title: Let's Encrypt
---

# Let’s Encrypt / ACME

WireBuddy contains an HTTP-01 ACME client that can request and locally store
single-domain certificates from Let’s Encrypt production or staging.

## Prerequisites

Before requesting a certificate:

1. The domain must resolve publicly to this server.
2. TCP port 80 must be reachable from the internet.
3. `http://DOMAIN/.well-known/acme-challenge/...` must reach WireBuddy.
4. The signed-in user must be an administrator.

If a reverse proxy terminates HTTP, forward the challenge path to WireBuddy:

```nginx
location /.well-known/acme-challenge/ {
    proxy_pass http://127.0.0.1:8000;
}
```

Do not redirect or intercept that path in a way that prevents the ACME server
from receiving WireBuddy's token response.

!!! tip
    Caddy and Traefik can obtain and renew certificates themselves. When the
    reverse proxy already manages TLS, use its ACME support instead of maintaining
    a second certificate lifecycle in WireBuddy.

## Request a certificate

Open **Settings → Let’s Encrypt**, select **Request Certificate**, and enter:

- the domain without a scheme or port;
- a valid account/contact email; and
- **Use staging environment** for test requests.

Staging certificates are not browser-trusted but are useful for validating DNS,
firewall, and proxy routing without consuming production rate limits.

WireBuddy creates the order, serves the HTTP-01 response for up to ten minutes,
and stores the issued files under:

```text
/app/data/certs/DOMAIN/
├── cert.pem
├── chain.pem
├── fullchain.pem
└── privkey.pem
```

Staging files use the `_staging` suffix. Certificate and chain files use mode
`0644`; private keys use `0600`. With the supplied Compose file, the matching
host path is `docker/data/certs/DOMAIN/`.

## Use the certificate

WireBuddy stores the files but does not switch its Uvicorn listener to HTTPS and
does not reconfigure or reload an external reverse proxy. Point your proxy's TLS
configuration at `fullchain.pem` and `privkey.pem`, then reload the proxy using
its normal deployment procedure.

There is no certificate-download API or UI action. Access the files through the
persisted data volume with appropriate host permissions.

## Expiry and renewal

The certificate list displays validity, expiry date, issuer, and remaining days.
A production or staging certificate is marked for renewal when it has 30 days or
less remaining. The UI then exposes **Renew**, which asks for an email and sends
a new request through the same issuance endpoint.

!!! warning "Renewal is manual"
    The current release does not run automatic ACME renewal or reload a TLS
    consumer. Monitor expiry externally and use the UI or API before the
    certificate expires.

The renewal-check endpoint reports production certificates that are due but does
not renew them itself.

## Delete versus revoke

The delete button removes the selected production or staging files from local
storage. It does **not** revoke the certificate at Let’s Encrypt. The current
release has no revocation endpoint.

If a private key is compromised, revoke it using an external ACME client or the
certificate authority's supported process, remove the local files, and issue a
new key and certificate.

## API endpoints

| Method | Endpoint | Access | Purpose |
|---|---|---|---|
| GET | `/api/acme/certificates` | signed-in user | List local certificates |
| POST | `/api/acme/certificates/request` | admin | Issue or renew a certificate |
| DELETE | `/api/acme/certificates/{domain}` | admin | Delete local files; `staging=true` selects staging |
| GET | `/api/acme/certificates/renewal-check` | admin | List production certificates due within 30 days |

The public challenge is served at
`/.well-known/acme-challenge/{token}`. The similarly named API challenge route
is an implementation endpoint and is not a certificate download.

## Troubleshooting

For failed validation, verify public DNS from outside the LAN, inbound TCP/80,
and reverse-proxy routing. Inspect the application log without exposing account
keys or challenge data:

```bash
docker compose --env-file .env -f docker/docker-compose.yml logs wirebuddy | grep -i acme
```

For repeated testing, use staging first. A missing `chain.pem` can occur only if
the CA response contains no intermediate certificate; `fullchain.pem` and
`privkey.pem` are the primary files for a reverse proxy.
