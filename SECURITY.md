# Security Policy

Kenato is designed around end-to-end encrypted 1-to-1 communication and minimal server knowledge.

## Supported versions

During pre-1.0 development, only the latest commit on the default branch is supported. The default branch is protected; M0 was closed only after the required repository rulesets and security settings were verified active. A formal stable-release support window will be defined before 1.0.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose user content, identities, cryptographic material, authentication data, service integrity, signing material, or the software supply chain.

Use GitHub Private Vulnerability Reporting for this repository when available. If that feature is temporarily unavailable, do not publish exploit details, credentials, tokens, private keys, or other secrets in a public issue while a private reporting path is being restored.

Please include, where safe:

- affected component and version/commit;
- security impact;
- minimal reproduction steps;
- proof of concept;
- suggested remediation if known.

Never include real production credentials or private user data in a report.

## Scope

Security reports may cover:

- Android application code and platform integration;
- the Go server;
- the versioned wire protocol;
- identity/cryptographic design when implemented;
- persistence and backup behavior;
- GitHub Actions, dependencies, build/release tooling, signing, and artifact provenance.

Reports about planned-but-not-yet-implemented features should identify the concrete current risk rather than a hypothetical future vulnerability.

## Response process

Best-effort targets during pre-1.0 development:

1. acknowledge a private report within 5 business days;
2. perform initial severity/impact triage within 10 business days;
3. keep the reporter informed when a confirmed issue requires longer remediation;
4. coordinate disclosure only after a fix or an explicit disclosure decision.

Urgent Critical/High issues may be handled faster. These targets are not a service-level agreement.

## Security principles

- Private identity keys stay on the device.
- The server must not be able to decrypt user messages or voice.
- Contact identity changes must not be silently trusted.
- Network and protocol inputs must be size- and state-bounded.
- Secrets and plaintext user content must not appear in logs.
- Cryptographic primitives must come from mature, reviewed implementations.
- Production signing material must never enter the repository or ordinary pull-request workflows.
