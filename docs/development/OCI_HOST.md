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

## Security state

The last captured interactive verification established:

- root SSH login disabled;
- password and keyboard-interactive SSH authentication disabled;
- public-key SSH authentication enabled;
- Fail2ban active for `sshd`;
- unattended package-update timers enabled;
- system clock synchronized with NTP active;
- Oracle-provided instance-service firewall rules preserved after host-firewall package recovery.

The following hardening items are desired before production use but are not treated by this repository document as verified runtime facts until fresh host evidence confirms them:

- persistent systemd journal with bounded retention;
- `auditd` active;
- AppArmor policy state verified;
- unused `rpcbind` disabled;
- conservative kernel/network sysctl hardening;
- final host-firewall policy preserving OCI instance-service rules;
- backup policy and restore test.

Source-IP restriction for SSH and final production perimeter rules are deliberately deferred. The development host must not be treated as a production security boundary, and this document is not a substitute for live host verification.

## Milestone boundary

M1 (`Local Identity`) is complete and remains entirely device-local. M2 (`Invite + Contact Establishment`) has not started; server-side identity publication, prekey upload, and invite/contact establishment belong to that milestone.

Do not expose the foundation server publicly merely because this host exists. The server remains loopback-bound by default until a reviewed deployment explicitly introduces a TLS boundary and required network policy.
