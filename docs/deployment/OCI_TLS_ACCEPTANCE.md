# OCI TLS/WSS boundary for M4.5 acceptance

Status: **review template; do not treat as live deployment evidence**.

This runbook exists only to make the already-reviewed M1-M4 stack reachable for the
closed #59 physical-device gate. It does not start M5 and does not make the OCI
development host a production environment.

## Security invariants

- `kenato-server` remains bound to `127.0.0.1:8080`.
- Only the reverse proxy may accept public HTTP(S) traffic.
- TCP 8080 must not be reachable through the OCI NSG/security list or host firewall.
- Public client traffic uses a dedicated DNS hostname with a publicly trusted certificate.
- TLS is terminated by Nginx and `/v1/messaging/ws` is proxied as WebSocket traffic.
- The backend does not trust `X-Forwarded-For`, `X-Real-IP` or other forwarded headers
  for authentication; the template deliberately strips them.
- Nginx access logging is disabled for this closed privacy-sensitive test. Error logging is
  warning-level and must never be augmented with request bodies, invite URIs, message
  plaintext, signatures or cryptographic material.
- SQLite state remains under `/var/lib/kenato` and is writable only by the dedicated
  `kenato` service account.
- Do not commit the live hostname, public IP, SSH material, certificate private keys,
  database files or host-specific firewall output.

## 1. Record the immutable deployment source

Before touching the host, record the exact reviewed commit to deploy:

```sh
git rev-parse HEAD
git status --short
```

The tree must be clean. Build the ARM64 binary from that exact commit on a trusted build
host:

```sh
cd server
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -o ../kenato-server ./cmd/kenato-server
cd ..
sha256sum kenato-server
```

Record the source SHA and binary SHA-256 in the #77 deployment evidence. Do not put the
host address or credentials in the issue.

## 2. OCI perimeter

Use the existing OCI VCN/public subnet, but review the effective Network Security Group
and/or security-list rules before changing them.

Required public ingress for the closed acceptance boundary:

- TCP 443 from the Internet for HTTPS/WSS;
- TCP 80 only for ACME HTTP validation and HTTPS redirect;
- TCP 22 only from the administrator source range already approved for SSH.

Explicitly verify there is **no public TCP 8080 ingress**.

Do not flush or replace the host firewall blindly. Oracle instance-service rules must be
preserved. Capture the pre-change state first:

```sh
sudo ss -ltnp
sudo nft list ruleset
```

If the host firewall needs adjustment, make the smallest additive change consistent with
the reviewed OCI perimeter and re-check the full ruleset afterward.

## 3. Dedicated service account and state

On the OCI Ubuntu host:

```sh
sudo useradd --system --home /var/lib/kenato --shell /usr/sbin/nologin kenato 2>/dev/null || true
sudo install -d -o kenato -g kenato -m 0700 /var/lib/kenato
sudo install -o root -g root -m 0755 ./kenato-server /usr/local/bin/kenato-server
sudo install -o root -g root -m 0644 deploy/systemd/kenato-server.service \
  /etc/systemd/system/kenato-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now kenato-server
```

Verify the backend is loopback-only:

```sh
sudo ss -ltnp | grep '127.0.0.1:8080'
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
```

A wildcard `0.0.0.0:8080` or `[::]:8080` listener is a deployment failure.

## 4. DNS and certificate bootstrap

Create a dedicated DNS A record for the acceptance hostname pointing at the OCI public
IPv4. Wait until the record resolves correctly from outside OCI.

Install Nginx and Certbot from Ubuntu's reviewed package sources:

```sh
sudo apt-get update
sudo apt-get install --yes --no-install-recommends nginx certbot python3-certbot-nginx
```

Before the certificate exists, create a temporary port-80-only Nginx server for the
dedicated hostname, verify `sudo nginx -t`, and reload Nginx. Then request the
certificate without disabling certificate verification:

```sh
sudo certbot certonly --nginx -d ACCEPTANCE_HOSTNAME
```

Do not use a self-signed certificate and do not weaken Android trust validation.

## 5. Install the reviewed Nginx boundary

Copy `deploy/nginx/kenato.conf.template` to a temporary file and replace every
`__KENATO_HOSTNAME__` token with the exact dedicated hostname. Inspect the result before
installing it.

The live file must retain:

- TLS 1.2/1.3 only;
- `client_max_body_size 128k`;
- per-source request and connection limits;
- WebSocket upgrade headers only on `/v1/messaging/ws`;
- `proxy_pass http://127.0.0.1:8080`;
- stripped forwarded-client-address headers;
- `access_log off`.

Install it as the only Kenato site, remove the temporary bootstrap site, then verify and
reload:

```sh
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl enable nginx
sudo systemctl enable --now certbot.timer
```

## 6. External HTTPS verification

From a machine outside the OCI host:

```sh
curl --fail --show-error --silent \
  --proto '=https' --tlsv1.2 \
  https://ACCEPTANCE_HOSTNAME/healthz
```

Expected response:

```json
{"status":"ok"}
```

Also verify HTTP redirects to HTTPS and does not serve the backend in cleartext:

```sh
curl --head http://ACCEPTANCE_HOSTNAME/healthz
```

The response must be an HTTPS redirect.

## 7. WSS upgrade verification

Use an ordinary TLS-validating client. A minimal HTTP/1.1 WebSocket upgrade probe can be
performed with curl:

```sh
headers="$(mktemp)"
ws_key="$(printf 'kenato-m45-probe' | openssl base64 -A)"
set +e
curl --http1.1 --silent --show-error --include --no-buffer \
  --max-time 3 \
  --dump-header "$headers" \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H "Sec-WebSocket-Key: $ws_key" \
  https://ACCEPTANCE_HOSTNAME/v1/messaging/ws >/dev/null
curl_status=$?
set -e
grep -Eq '^HTTP/1\.[01] 101 ' "$headers"
rm -f "$headers"
test "$curl_status" -eq 0 || test "$curl_status" -eq 28
```

The short timeout is expected because an unauthenticated Kenato socket remains open only
long enough for the protocol challenge/response. The important result is a TLS-validated
`101 Switching Protocols`, not successful application authentication.

## 8. Final host checks

On the server:

```sh
sudo systemctl --no-pager --full status kenato-server nginx
sudo ss -ltnp
sudo stat -c '%U %G %a %n' /var/lib/kenato
sudo find /var/lib/kenato -maxdepth 1 -type f -printf '%m %u %g %p\n'
```

Required:

- `kenato-server` listens only on `127.0.0.1:8080`;
- Nginx owns public 80/443;
- no other public Kenato listener exists;
- `/var/lib/kenato` is owned by `kenato:kenato` and mode 0700;
- SQLite database files are service-owned and mode 0600.

## 9. Android acceptance origin

On both physical devices running the acceptance-capable M4.5 build, enter exactly:

```text
https://ACCEPTANCE_HOSTNAME
```

Do not use an IP literal, `http://`, a URL path, a query string, or a certificate-bypass
tool. The Android acceptance UI intentionally rejects those forms.

Proceed with #59 only after both external HTTPS and WSS probes pass.

## 10. Rollback

If any boundary check fails:

1. stop physical acceptance;
2. disable the Kenato Nginx site or close public 80/443 at the OCI perimeter;
3. keep `kenato-server` loopback-only;
4. preserve the SQLite state files for diagnosis unless a separately reviewed destructive
   recovery action is required;
5. record only non-secret failure evidence in #77.

A rollback must never expose `:8080` publicly as a shortcut.
