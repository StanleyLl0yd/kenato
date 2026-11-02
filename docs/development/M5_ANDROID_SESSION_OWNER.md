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

## Foreground callback fencing (research-only UI)

The controller stamps foreground refreshes, silent refreshes and explicit
operation results with the UI epoch captured **before** dispatching background
work. A worker may finish building a snapshot after Activity pause/resume,
but must not relabel old QR/proof output as belonging to the new foreground.
The UI snapshot guard rejects callbacks from a previous Activity epoch and
must **not** release the `busy` flag of a newer UI operation. Only a
matching-epoch operation callback or fresh foreground snapshot may clear it.
JVM regressions cover stale QR output, preservation of the newer busy flag
and eventual matching-epoch release.
The controller's worker serialization does **not** establish a durable
M2/M3/M4/M5 transaction or replace physical lifecycle tests.

## Exact-operation completion fencing

Further asynchronous review identified a second race: a foreground refresh
posted during an unrelated same-epoch operation could call `applySnapshot()`
and clear `busy` early. Conversely, ignoring all older-epoch operation
completions could leave the UI permanently busy after Activity pause/resume.

The controller now gives each explicit operation a monotonic main-thread ticket.
Foreground refreshes cannot release an outstanding operation. The precise
ticket may release the busy flag after an epoch transition but discards the
obsolete snapshot, signed QR, notice and error; a fresh silent refresh runs
afterwards. A stale ticket can never release a newer action. Three JVM
regressions assert this operation/epoch distinction. This remains process-local
UI correctness only: not a durable M3/WSS lifecycle transaction or physical
P17 acceptance.

## Process-local M1/M2/M3 repository ownership

Follow-up semantic review found that Android factory callers constructed
independent `LocalIdentityRepository` (M1) and `ContactLocalState` (M2)
monitors over the same SharedPreferences files. A per-instance
`@Synchronized` cannot serialize these independent factory objects.
The M45 controller, contact repository, session coordinator and messaging
boundary now use dedicated process-local M1 and M2 singleton factories,
keyed by canonical app `noBackupFilesDir`, alongside the M3 singleton.
The common `ProcessLocalOwnerRegistry` has concurrent-construction,
same/different directory and failed-create retry JVM regressions.

**Security limit:** these are **three independent** per-store monitors,
not one transaction or durable root owner. An M2 pin mutation may still
interleave with M3 ratchet/handoff, M4 WSS state and M5 semantic/effect
claims. Multiple app processes have no common lock, and file rollback
is not addressed by this factory consolidation. #116 shared durable
M2/M3/WSS/effect owner, P13/P14/P17 physical acceptance and #118/#170/#171
anti-rollback research remain mandatory before audio activation.

## Runtime-local serialized transport admission

The acceptance runtime now serializes trust/session mutations, explicit WSS
start/stop, outbound text staging and close on its own monitor. An explicit
start cannot resume the same runtime's transport while an invite/bootstrap
mutation is still running. A two-worker JVM regression holds M3 bootstrap
between trust mutation and completion and verifies that a second caller
cannot start WSS until the mutation completes.

This is **only a single-runtime process monitor**, not a process-wide WSS
lease or a multi-store/M2 consent transaction. Distinct runtime instances,
interprocess operation, M3/consent rollback and pending network callbacks
remain separate pre-voice acceptance blockers; no media or v2 transport is
activated by this change.
