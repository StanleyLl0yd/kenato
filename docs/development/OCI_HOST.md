# OCI Development Host

Kenato's initial non-production development host is an Oracle Cloud Infrastructure compute instance in the Germany Central (Frankfurt) home region.

## Current baseline

- Provider: Oracle Cloud Infrastructure (OCI)
- Region: Germany Central (Frankfurt)
- Compute: Ampere A1 (`VM.Standard.A1.Flex`)
- Architecture: ARM64 / AArch64
- Operating system: Ubuntu 24.04 LTS Minimal
- Capacity: 2 OCPU / 12 GB RAM
- Boot volume: approximately 47 GB
- Network: public IPv4 through a dedicated VCN/public subnet; IPv6 is not currently configured
- Local administrator account: `ubuntu`, SSH public-key authentication only

The instance public IP, SSH private keys, host fingerprints, credentials, and other host-specific secrets are operational data and must not be committed to this repository. Administrators should keep a local SSH alias such as `kenato` in `~/.ssh/config`.

## Security baseline

The development host is intentionally kept minimal. The current baseline includes:

- root SSH login disabled;
- password and keyboard-interactive SSH authentication disabled;
- public-key SSH authentication enabled;
- Fail2ban for `sshd`;
- unattended package security updates;
- persistent systemd journal with bounded retention;
- `auditd` enabled;
- AppArmor enabled;
- unused `rpcbind` disabled;
- conservative kernel/network sysctl hardening;
- Oracle-provided instance-service firewall rules preserved.

Source-IP restriction for SSH and final production perimeter rules are deliberately deferred until the deployment milestone. The development host must not be treated as a production security boundary.

## Milestone boundary

M1 (`Local Identity`) is device-local. It must not depend on this host or require deploying the Kenato backend. Server-side identity publication, prekey upload, and invite/contact establishment belong to M2.

Do not expose the M0 server skeleton publicly merely because this host exists. The server remains loopback-bound by default until a reviewed deployment explicitly introduces a TLS boundary and required network policy.
