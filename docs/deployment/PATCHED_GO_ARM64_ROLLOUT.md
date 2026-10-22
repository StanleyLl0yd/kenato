# Go 1.27.2 Linux ARM64 backend rebuild and guarded rollout

Status: **build preparation only** for #91. No live deployment, backend
feature change, new Kenato server, release signing, TURN, or M6.

## Produce and verify a reviewed-source binary

The reviewed merge that adds this workflow triggers one build on `main`;
later rebuilds may be run manually from **Verified Go ARM64 backend artifact**.
A push upload is never deployment approval. Require successful exact-main
CI/security checks before trusting its output. The job rejects non-`main`
refs; its checkout is checked against
`GITHUB_SHA`. The pinned Go 1.27.2 toolchain builds with
`GOTOOLCHAIN=local`, `GOOS=linux`, `GOARCH=arm64`, `CGO_ENABLED=0`,
`-trimpath`, and embedded VCS revision. Go unit tests, module verification,
ELF architecture, build metadata, clean tree and SHA-256 verification must
all pass before artifact upload.

The Actions ZIP contains the Linux ARM64 binary, `SHA256SUMS`,
`GO_BUILD_INFO.txt` and `PROVENANCE.txt`. It is an **unsigned, temporary
build artifact**, not a release or supply-chain attestation. No signing key,
OCI access credential, deployment operation or SQLite data enters CI.

Before host use, verify the downloaded artifact is from a successful Actions
run attached to the **expected exact reviewed main SHA**. Check that
`PROVENANCE.txt` and `GO_BUILD_INFO.txt` agree with that SHA and the pinned
Go/ARM64 settings. Within the downloaded artifact directory:

```sh
sha256sum --check SHA256SUMS
go version -m ./kenato-server-linux-arm64
readelf -h ./kenato-server-linux-arm64
```

Record only the source SHA, binary SHA-256, Actions run ID, source/toolchain
verification and operator approval in #91. Do not record the host address,
secrets, raw requests, user identities or databases.

## Guarded on-host operator helper (proposal; not yet deployed)

A reviewed, **manual-only** helper at
`scripts/rollout_existing_oci_arm64.sh` stages the exact existing Go
1.27.2 ARM64 artifact on the **existing host only**, validates local checksums,
source/provenance fields, binary architecture, existing service ownership,
pre-change service health and loopback-only port, preserves the original binary
under `/var/backups/kenato`, performs an atomic executable replacement and
checks systemd, local HTTP health, listener scope and `/proc/<pid>/exe`
binary digest. Failures after service stoppage trigger automatic local
executable rollback and a health recheck. No SSH, firewall, Nginx, TLS, SQLite,
secrets, server feature, additional host or TURN changes are attempted.

**This script is not evidence of deployment**: it has not been run on OCI.
Before executing it, the host operator must independently authenticate the
GitHub Actions ZIP digest and inner `SHA256SUMS`, authorize a change window,
review the script and copy the extracted files to an operator-controlled
directory on the real host. Then on the host:

```sh
sudo bash scripts/rollout_existing_oci_arm64.sh --apply /path/to/extracted-artifact 04f8d78c3d730d512a9bca6462a4f4177db6ff58
```

The source SHA is the **original verified backend artifact's** source, not
the latest Android-only `main` SHA. The script deliberately refuses to
create an absent service or install onto an unhealthy host. A successful
local result is not enough: independently test public HTTPS and authenticated
WSS, document the backup and rollback readiness, and only then close #91.

## Operator-controlled deployment gate

The live OCI host was previously reported to run an older Go-built binary.
CI success does not patch a running host. No automatic rollout is provided.

A separately authorized operator must:

1. Confirm change window, current service health, source/bin SHA and exact
   OS/ARM64 target. Confirm the existing reverse proxy and SQLite state
   remain unchanged.
2. Securely transfer and independently check the binary checksum on the host.
   Preserve the previously deployed executable for immediate rollback, with
   restrictive ownership and permissions. Keep existing SQLite data untouched.
3. Stop **only** the existing `kenato-server` systemd unit, atomically
   replace `/usr/local/bin/kenato-server` with the verified root-owned
   executable, then start the unit. Do not change network listeners, TLS,
   service privileges or systemd hardening.
4. Check `systemctl status kenato-server`, verify the process binary's
   `go version -m` and SHA, confirm a loopback-only
   `127.0.0.1:8080` listener, and require
   `curl --fail http://127.0.0.1:8080/healthz` to succeed.
   Recheck public HTTPS health and authenticated WSS compatibility according
   to `docs/deployment/OCI_TLS_ACCEPTANCE.md`.
5. If checks fail, stop that unit, restore the exact prior executable, restart
   and recheck health. Record the failed patch rollout as a blocker rather than
   claiming the runtime is patched. Preserve database files for diagnosis.

Do not expose port 8080 publicly or bypass certificate verification during
recovery. Mark #91 completed only after the running executable and health
have been independently verified and the patch is actually deployed.
