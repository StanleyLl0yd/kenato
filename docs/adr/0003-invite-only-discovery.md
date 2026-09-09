# ADR 0003: Invite-Only Contact Discovery

Status: Accepted

## Context

Kenato does not require phone numbers, email addresses, public usernames, or address-book upload.

Public discovery increases enumeration, spam, metadata, and abuse surface.

## Decision

Contacts are established only through explicit invites.

There will be no public user search in 1.0.

Default invite policy:

- cryptographically random token;
- single use;
- 24-hour expiry;
- server stores a hash rather than the raw invite token where practical.

## Consequences

Positive:

- no public user enumeration;
- reduced spam surface;
- minimal server-side social graph;
- simple privacy model.

Negative:

- users must exchange an invite out-of-band;
- discoverability is intentionally limited.

This is a product principle, not merely an MVP shortcut.
