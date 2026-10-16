# M5 Android M3 session ownership checkpoint

Scope: #116 client runtime preparation only. No voice transport, microphone,
WebRTC dependency, server, or release activation.

## Same-instance bootstrap and messaging

The M4.5 Android acceptance factory used to construct two independent
`LocalSessionRepository` instances against one M3 AtomicFile: one behind
`SessionCoordinator.create` for bootstrap and one behind
`AndroidM45MessagingBoundary` for WSS messaging and outbound sends.
`LocalSessionRepository` uses instance-level synchronized operations, so
these separately created objects do not share a Kotlin monitor.

The updated `M45AcceptanceRuntime.create` constructs **one** M3 repository
and injects it into both bootstrap and messaging. It preserves the existing
M4.5 transport pause/resume ordering for invite and session operations and
does not alter M3 storage bytes or enable M5 v2 stage/send operations.
Existing direct callers of `SessionCoordinator.create(context, origin)`
also receive the process-shared repository through its default factory argument;
explicit injection ensures the same owner is used within this runtime.

## Process-local reuse, not a complete M5 transaction boundary

`LocalSessionRepository.create(context)` now reuses one repository for a
canonical app `noBackupFilesDir` within the **same process**, including
separately constructed Activities and acceptance runtimes. The synchronized
registry ensures the factory creates exactly one owner per storage location.
Its `@Synchronized` repository methods therefore share one M3 monitor.
Different storage locations do not share an owner; failed factory creation is
not cached. Direct test-only constructor calls bypass the Android factory.

This is **not** an inter-process, durable, or multi-store transaction lock.
Overlapping callbacks can still interleave *between* repository operations;
M2 contact/consent state, M4 history, WSS lifecycle, and future M5 voice
admission are not made atomic by this registry. Voice stays disabled.
Do not claim that #116's complete single-owner/consent requirement is met.

Before any production M5 integration:

- Specify and test one lifecycle owner for all M3 ratchet advancement,
  durable voice handoffs, inbound WSS recovery and outbound staged sends.
- Revalidate pinned M2 identity and signed capability at a shared
  admission/commit boundary; preserve exact single-use claims.
- Test activity recreation, simultaneous send/bootstrap, process kill and
  restart, failed write, and pending-ACK replay/expiry on physical phones.
- Resolve the proposed #118 M3 at-rest migration/rollback design separately.
- Require #87 repository-wide and two-phone acceptance. Keep 0.0.4 unchanged.

JVM tests cover transport stop/start around bootstrap, failed trust
mutation, and process-registry identity/concurrent factory creation. They
do **not** prove Android Context factory wiring, inter-process exclusion or
multi-step M3/M2/M4 transaction semantics. Activity recreation and physical
device verification remain requirements.
