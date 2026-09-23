#!/usr/bin/env python3
"""Verify the reviewed M4.5 OCI TLS/WSS deployment contract."""

from __future__ import annotations

import re
from pathlib import Path

errors: list[str] = []


def read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"{path}: unable to read: {error}")
        return ""


def require(path: str, text: str, *fragments: str) -> None:
    for fragment in fragments:
        if fragment not in text:
            errors.append(f"{path}: missing required deployment control {fragment!r}")


systemd_path = "deploy/systemd/kenato-server.service"
nginx_path = "deploy/nginx/kenato.conf.template"
doc_path = "docs/deployment/OCI_TLS_ACCEPTANCE.md"

systemd = read(systemd_path)
nginx = read(nginx_path)
doc = read(doc_path)

require(
    systemd_path,
    systemd,
    "User=kenato",
    "Group=kenato",
    "WorkingDirectory=/var/lib/kenato",
    "Environment=KENATO_LISTEN_ADDR=127.0.0.1:8080",
    "Environment=KENATO_DB_PATH=/var/lib/kenato/kenato.db",
    "Environment=KENATO_MAILBOX_DB_PATH=/var/lib/kenato/kenato-mailbox.db",
    "ExecStart=/usr/local/bin/kenato-server",
    "UMask=0077",
    "NoNewPrivileges=true",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "ReadWritePaths=/var/lib/kenato",
)

for forbidden in (
    "KENATO_LISTEN_ADDR=0.0.0.0",
    "KENATO_LISTEN_ADDR=:8080",
    "EnvironmentFile=",
):
    if forbidden in systemd:
        errors.append(f"{systemd_path}: forbidden deployment fragment {forbidden!r}")

require(
    nginx_path,
    nginx,
    "server_name __KENATO_HOSTNAME__;",
    "listen 80;",
    "listen 443 ssl http2;",
    "ssl_protocols TLSv1.2 TLSv1.3;",
    "ssl_session_tickets off;",
    "client_max_body_size 128k;",
    "access_log off;",
    "limit_req_zone $binary_remote_addr zone=kenato_http_per_ip:10m rate=30r/s;",
    "limit_req_zone $binary_remote_addr zone=kenato_ws_per_ip:10m rate=12r/m;",
    "limit_conn_zone $binary_remote_addr zone=kenato_conn_per_ip:10m;",
    "location = /v1/messaging/ws",
    "proxy_pass http://127.0.0.1:8080;",
    "proxy_http_version 1.1;",
    "proxy_set_header Upgrade $http_upgrade;",
    "proxy_set_header Connection $connection_upgrade;",
    'proxy_set_header X-Forwarded-For "";',
    'proxy_set_header X-Forwarded-Proto "";',
    'proxy_set_header X-Real-IP "";',
    "proxy_buffering off;",
)

for forbidden in (
    "listen 8080",
    "proxy_pass http://0.0.0.0",
    "proxy_pass https://127.0.0.1:8080",
    "ssl_protocols TLSv1 ",
    "ssl_protocols TLSv1.1",
    "proxy_ssl_verify off",
    "$proxy_add_x_forwarded_for",
):
    if forbidden in nginx:
        errors.append(f"{nginx_path}: forbidden deployment fragment {forbidden!r}")

if nginx.count("__KENATO_HOSTNAME__") < 4:
    errors.append(f"{nginx_path}: hostname must remain an explicit deployment template")

# Do not let host-specific public addresses accidentally become repository configuration.
for path, text in ((nginx_path, nginx), (doc_path, doc)):
    for match in re.finditer(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", text):
        value = match.group(0)
        if value not in {"127.0.0.1", "0.0.0.0"}:
            errors.append(f"{path}: host-specific public IPv4 is forbidden: {value}")

require(
    doc_path,
    doc,
    "kenato-server remains bound to",
    "TCP 8080 must not be reachable",
    "Oracle instance-service rules must be preserved",
    "publicly trusted certificate",
    "Do not use a self-signed certificate",
    "101 Switching Protocols",
    "A rollback must never expose",
    "M5",
)

if "https://ACCEPTANCE_HOSTNAME" not in doc:
    errors.append(f"{doc_path}: acceptance origin placeholder is required")
if "http://ACCEPTANCE_HOSTNAME" not in doc:
    errors.append(f"{doc_path}: cleartext redirect verification is required")

if errors:
    for error in errors:
        print(f"ERROR: {error}")
    raise SystemExit(1)

print("M4.5 deployment contract: OK")
