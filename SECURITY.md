# Security Policy

Kenato is designed around end-to-end encrypted 1-to-1 communication and minimal server knowledge.

## Reporting a vulnerability

Please do not open a public issue for vulnerabilities that could expose user content, identities, cryptographic material, authentication data, or service integrity.

Until a dedicated security contact is published, use GitHub's private security reporting feature when available for this repository.

Include:

- affected component and version/commit;
- impact;
- reproduction steps;
- proof of concept where safe;
- suggested remediation if known.

## Security principles

- Private identity keys stay on the device.
- The server must not be able to decrypt user messages or voice.
- Contact identity changes must not be silently trusted.
- Network and protocol inputs must be size- and state-bounded.
- Secrets and plaintext user content must not appear in logs.
- Cryptographic primitives must come from mature, reviewed implementations.

## Supported versions

During pre-1.0 development, only the latest development version is supported. A formal support window will be defined before the first stable release.
