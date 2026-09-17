# M4 Android Messaging Security Review

Status: #53 Android messaging/history implementation is complete and was revalidated by the completed #54 final repository-wide M4 verification. This review records the completed Android authenticated WSS client, durable M3 message handoff, local one-to-one conversation history and minimal application-facing messaging boundary. Server mailbox/routing reviews remain in the existing M4 protocol/mailbox/transport documents. M5 calling and background/push behavior are out of scope.

## Trust and crypto boundary

M4 Android messaging does not introduce a second cryptographic session system. It uses the completed M3 vodozemac Olm session bound to the pinned M2 Kenato identity. The transport never receives a plaintext-to-encrypt callback and never re-encrypts a retry.

Outbound text is first encoded as the bounded canonical M4 plaintext record containing sender identity, recipient identity, random non-zero message id, sent/expiry timestamps and text. `LocalSessionRepository.encryptAndStageMessageHandoff` encrypts that exact record once and atomically persists both the advanced M3 ratchet snapshot and the exact immutable M4 envelope handoff. If envelope construction, provenance validation or the atomic write fails, the ratchet advancement is not published to callers.

Outbound staging takes one stage-time snapshot before recovery/admission. The same timestamp is used for the new plaintext `sent_at`, derived expiry and local envelope validation. Current-time expiry is checked again at the WSS boundary before an unsent durable envelope is queued, so clock movement during native encryption cannot turn a valid logical stage into a partial ratchet/history failure.

Inbound processing first validates the authenticated outer envelope and the canonical `SessionCiphertext` wrapper. The wrapper sender/recipient must match the routing envelope before session lookup/native decrypt. M3 decrypt plus the recoverable plaintext/envelope handoff are committed in one atomic session-state update only after the decrypted canonical plaintext matches the expected owner/contact/session context and exact outer sender/recipient/message-id/expiry.

The WSS receive boundary takes one receive-time snapshot. Outer-envelope validation and the durable handler's post-decrypt inner/outer validation both use that same snapshot. This prevents a valid delivery from changing security outcome merely because the clock crosses the exact TTL boundary while decryption/history work is in progress.

## Crash-safe outbound lifecycle

A logical send has two durability layers:

1. the M3 session store atomically advances the ratchet and retains the exact ciphertext/envelope handoff;
2. the conversation-history store records the same authenticated message key as `PENDING_ACCEPTANCE` before the transport is asked to send it.

The sender performs history capacity preflight before advancing the ratchet. After the atomic M3 handoff exists, a history write failure does not trigger re-encryption: restart recovery imports the exact staged plaintext/envelope into history and then reuses the exact staged envelope bytes.

Sender admission uses an outbound-only recovery path. It may reconcile staged outbound envelopes and terminal outbound cleanup, but it deliberately does not import or remove inbound handoffs and never creates inbound ACK work as a side effect of a foreground send attempt. Full inbound/outbound recovery remains owned by the WSS lifecycle, which is also responsible for emitting the resulting durable ACK work. This separation prevents foreground sending from racing the WSS inbound delivery/ACK path.

`SendAccepted` is applied in crash-safe order: conversation history becomes `ACCEPTED` first, then the M3 staged envelope is removed. A crash between those writes is recovered by observing durable `ACCEPTED` and deleting the leftover handoff without resending.

A staged outbound message that reaches its protocol TTL without a durable `SendAccepted` is persisted as terminal `EXPIRED` before its staged M3 handoff is removed. Application code exposes this as `EXPIRED_UNCONFIRMED`, not as a claim that the recipient definitely did not receive the message: an earlier WebSocket enqueue or server receipt may have succeeded while the acceptance response was lost. A crash after the terminal history write is recovered without another send.

Before admitting a fresh logical send, the sender recovers older durable outbound work and evaluates it through `WssMessagingOutboundAdmission`. That admission boundary synchronizes on the same coordinator monitor used by WSS callbacks and live flush. When no authenticated WSS exists, no application envelope can become newly in flight during the decision, so expired offline work may be durably terminalized before the **32 staged outbound sends** admission count is evaluated. Thus a device disconnected past TTL cannot be permanently blocked by 32 expired offline work items.

While WSS is `AUTHENTICATED`, sender-side terminalization is deliberately deferred for all recovered sends. The transport retains exact per-key in-flight authority: an envelope that has already been accepted by `sendBinary` must remain eligible for a later `SendAccepted`, even if its TTL crosses before the acceptance frame arrives. This conservative authenticated-state rule also removes the check-then-send race between admission and `pumpRecovery`; WSS socket work and admission use the same monitor. The WSS transport itself terminalizes only recovered keys not already in `sentThisConnection` before queueing them.

Terminal recovery is idempotent. A stale recovery plan that observes history already `ACCEPTED`, or already `EXPIRED` after its staged handoff was cleaned, is terminal and cannot resurrect work or turn a correct late cleanup into a failure.

## Crash-safe inbound lifecycle and duplicate handling

Inbound M3 decrypt advances the ratchet before plaintext can leave the M3 boundary. Therefore network ACK is forbidden until the recoverable plaintext/envelope handoff has entered the separate durable history store.

The order is:

1. validate outer envelope and canonical M3 ciphertext provenance;
2. decrypt once and atomically persist advanced ratchet plus exact recoverable inbound handoff;
3. import the canonical plaintext and SHA-256 digest of the exact canonical envelope into history as `PENDING_ACK`;
4. remove the M3 handoff;
5. only then return an ACK to transport.

If the history write fails, the session handoff remains. If cleanup fails after history commit, a retry recognizes the exact authenticated envelope digest in history and ACKs without a second decrypt/ratchet advance. Reuse of the same authenticated sender/message-id with different envelope bytes fails closed before native decrypt.

At-least-once delivery is therefore idempotent at the authenticated `(peer identity id, message id, direction)` history key while ciphertext substitution remains detectable.

## Conversation history format and bounds

Conversation history uses a dedicated Android `AtomicFile` under `applicationContext.noBackupFilesDir`. The stable filename remains `kenato_conversation_history_v1.state`; the internal record format is versioned independently and currently encodes version 2 while retaining strict version-1 decode compatibility for pre-expiry-state data.

The format has `KNH4` magic, an explicit version, owner identity id, bounded records and a trailing SHA-256 checksum compared with `MessageDigest.isEqual`. Corruption, unsupported version, owner mismatch, duplicate authenticated idempotency keys, non-canonical plaintext or provenance mismatch fails closed.

Retention is bounded to:

- at most **1000 messages / 4 MiB** per conversation;
- at most **4096 messages / 16 MiB** globally for the local history state.

Pruning is deterministic and restricted to records already safe to forget. Outbound `ACCEPTED` and terminal `EXPIRED` records may be pruned oldest-first. Inbound `PENDING_ACK` records become prunable only at or after their authenticated plaintext expiry, when a newly received copy would already be rejected as expired. Outbound `PENDING_ACCEPTANCE` is never pruned merely because it is old or because capacity is full.

The M3 session handoff journal is independently bounded to 64 entries / 4 MiB, with individual plaintext/envelope bounds. Normal outbound admission additionally caps active staged sends at **32 staged outbound sends**, so the WSS layer cannot silently grow an unbounded logical send queue. Expired offline work is reconciled out of that active count only while transport ordering proves no authenticated in-flight race is possible.

## Authenticated WSS lifecycle

Android uses the exact-pinned OkHttp `5.5.0` dependency for the M4 WebSocket adapter. `OkHttpMessagingSocketFactory` owns its dedicated client instead of accepting an externally configured/shared client. HTTP redirects and HTTPS↔HTTP redirects are explicitly disabled, so a server response cannot move the reviewed `wss://host[:port]/v1/messaging/ws` handshake to another origin. The client adds no logging interceptor, custom trust manager, hostname override or alternate TLS stack; certificate and hostname validation remain OkHttp/platform defaults.

A service origin must be a bare HTTPS origin and the coordinator derives the exact `wss://host[:port]/v1/messaging/ws` endpoint. Application frames are binary only and bounded by the shared 100 KiB wire-frame limit. Text frames fail closed. One coordinator owns at most one active socket.

Connection authentication reuses the long-lived Kenato P-256 identity. The client validates the server challenge, signs the canonical `KENATO-MESSAGING-AUTH-V1` payload and does not send/recover application work until the server confirms authentication.

Ordinary connection establishment/loss uses bounded delays of 1, 2, 4, 8, 16, 30, 30 and 30 seconds, with at most eight automatic retries per connection-failure episode. Authentication has a 15-second client timeout. Successful authentication resets only this ordinary connection retry budget.

Durable outbound work has a separate **eight-attempt durable retry budget** with the same bounded 1/2/4/8/16/30/30/30-second backoff. A successful re-authentication does **not** reset that budget, because re-auth alone proves no progress for a staged message still awaiting durable `SendAccepted`. The budget resets when `SendAccepted` durably advances message state, when recovery proves that no staged outbound work remains (including after terminal expiry), or when the coordinator is explicitly stopped/started. An authenticated close or network failure consumes this durable budget only while a staged outbound send is actually in flight. Recovered inbound ACKs are idempotent but have no `SendAccepted`, so an ACK-only connection loss remains on the ordinary connection retry path rather than exhausting an unrelated outbound budget.

A server `RETRY_LATER` carrying a message id is correlated against current durable work. If it names an in-flight outbound send, the outbound durable retry budget and exact-envelope reconnect path apply. If it names a recovered or just-produced delivery ACK, Android uses a separate **bounded ACK retry budget**: at most eight same-socket retries with the same 1/2/4/8/16/30/30/30-second backoff. ACK retry does not invent an acknowledgement-of-ACK that the protocol does not provide. After the local ACK retry budget is exhausted, the durable history record remains `PENDING_ACK`; no automatic reconnect loop is started merely for cleanup, and a later natural reconnect can replay the idempotent ACK again. An uncorrelated message-specific `RETRY_LATER` fails closed.

Recovery after authentication is derived only from durable state. Same-connection sets suppress duplicate sends and recovered ACKs except when a correlated ACK retry explicitly re-enables the affected message id. A WebSocket queue failure causes reconnect so durable work can be replayed on the next authenticated connection; it is not treated as successful delivery.

An authenticated connection also has a **30-second send-acceptance watchdog** while at least one staged outbound envelope has been queued but not durably acknowledged by `SendAccepted`. The watchdog is anchored when the first unresolved send is queued; additional sends cannot extend it indefinitely. If unresolved staged work remains when it fires, the socket is cancelled and the separate bounded durable retry path replays the exact durable envelope bytes after re-authentication. Once all same-connection sends have been accepted, the watchdog is cancelled. This bounds half-open connections and lost server-confirmation frames without re-encrypting or advancing the ratchet again.

The server-side counterpart does not silently discard a success/error response when its bounded per-peer outbound queue is full: failure to enqueue a `SendAccepted` or send-result error closes that authenticated peer, allowing the Android durable replay path to recover. Transient route/storage failures default to `RETRY_LATER`; explicit mailbox rejection and exact message-id conflict remain `SEND_REJECTED` and fail closed on Android.

`flushDurableWork()` is only a best-effort wake-up for an already authenticated socket. It is a no-op before authentication/offline and does not own plaintext, sessions or encryption.

## Local data and backup policy

Plaintext conversation history is intentionally local to the device and therefore treated as sensitive application data.

The history file is under `noBackupFilesDir`, not normal files, cache, shared preferences or external storage. In addition, the application manifest sets `android:allowBackup="false"`, references both legacy and Android 12+ backup-policy resources, and sets `android:usesCleartextTraffic="false"`. The backup rules exclude all normal and device-encrypted root/file/database/shared-preference domains plus external storage from cloud backup and device transfer.

M4 messaging production code does not intentionally write plaintext, ciphertext bodies, message ids, identities, signatures or session material to Android logging APIs, console output or stack-trace helpers. Message text/history is not placed in `SavedStateHandle`, notifications, clipboard or shared preferences. The minimal application conversation API returns data directly from validated durable history; a later UI/background milestone must not weaken this boundary without a separate review.

No background service, push wake-up, notification preview or lock-screen message-content behavior is introduced by #53.

## Failure and corruption behavior

The Android layer fails closed for:

- owner/peer identity size or self-peer mismatch;
- missing pinned M3 session;
- non-canonical plaintext, envelope or `SessionCiphertext` encoding;
- inner/outer identity, message-id or expiry mismatch;
- local session crypto-context substitution;
- history/session checksum or owner mismatch;
- conflicting authenticated message-id reuse;
- unsupported persisted format/state;
- malformed/authentication-failed/send-rejected WSS frames;
- uncorrelated message-specific retry errors;
- impossible recovery state such as pending history without its recoverable staged envelope.

Durability failures are not converted into ACK/send success. Recovery keeps the exact staged material until the next safe state transition.

## Dependency and privacy posture

The new Android network dependency is exact-pinned in the Gradle version catalog and remains covered by Dependency Review, Android/CodeQL build paths and repository-wide `make test`. The dedicated WSS client relies on platform/OkHttp TLS validation, disables redirect follow-ups, and cannot be replaced at construction with a separately configured application client.

M4 does not claim metadata hiding from the Kenato server. Routing identities, random message id, expiry, ciphertext size, connection timing and delivery bookkeeping remain server-visible by design. Ordinary text and semantic application content remain inside M3 authenticated ciphertext on the network/server boundary.

## Verification requirements

The completed #53 implementation evidence revalidated by #54 includes:

- session-state v1→v2 and conversation-history v1→v2 migration tests must pass;
- outbound/inbound atomic handoff failure and restart windows must pass;
- foreground outbound recovery must leave inbound handoffs/ACK state untouched;
- offline/reconnect/live flush must reuse exact staged envelope bytes without re-encryption;
- a missing `SendAccepted` must trigger the bounded acceptance watchdog, durable reconnect and exact-envelope replay without re-auth resetting the durable retry budget;
- authenticated close/network failure with staged work in flight must consume the same bounded durable retry budget across re-authentication;
- ACK-only disconnects must remain on the ordinary connection retry path, terminalized outbound work must not reduce the retry budget available to a later message, and correlated ACK `RETRY_LATER` handling must stay within the separate bounded ACK retry budget without forced reconnect;
- server response-queue backpressure must disconnect rather than silently lose `SendAccepted`, transient route/storage failures must remain retryable, and permanent message-id conflicts/rejections must remain terminal;
- duplicate/conflicting envelope and canonical-ciphertext tests must pass;
- expiry-before-send, offline-expiry admission, authenticated in-flight deferral, terminal-idempotence and receive-time-boundary tests must pass;
- the dedicated WSS OkHttp client must keep redirects disabled and contain no application interceptors;
- safe pruning must respect pending-send/pending-ACK durability rules;
- the minimal conversation API must expose only validated durable records;
- Android lint/unit/build and repository-wide `make test` must pass;
- `scripts/verify_m4_android_messaging.py` must remain part of repository `make test`;
- all protected-branch exact-head checks must be green.

Issue #54 final repository-wide M4 end-to-end/security verification is complete. M4 closure is verified; #59/M4.5 is the next permitted work. M5 calling is not part of this review and remains blocked until #59 completes.
