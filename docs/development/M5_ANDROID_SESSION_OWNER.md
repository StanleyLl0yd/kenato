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

### Stale queued WSS-start rejection

A simple monitor was insufficient on the failure path: a start requested
*during* an unfinished mutation could wait for the monitor and then restart
WSS immediately after the mutation failed. The runtime now captures a volatile
mutation epoch **before** taking its start monitor and rejects actions whose
epoch changed or was in progress. The epoch advances on both successful and
failed trust mutations, and a subsequent fresh explicit start remains possible.
Two-worker JVM cases check both success and failure, including a queued stale
start after a failed bootstrap. This is not durable, cross-runtime admission.

### Closed owner denies transport resurrection

`close()` now sets an idempotent terminal state before disposing of WSS and
scheduler resources, including when transport shutdown throws. Later or queued
start, trust mutation and outbound staging cannot reuse a closed runtime; stop
and close remain idempotent. A JVM regression checks denied reopen/staging.
This does not replace Android lifecycle/device tests or the missing shared
M2/M3/WSS/effect transaction.

## Partial WSS start and failed-stop fencing

A WSS `start()` call may activate transport before throwing; treating that
exception as "not started" could leave a live socket through a later contact
or M3 trust mutation. The acceptance runtime now attempts explicit `stop()`
on any failed start, including the automatic post-mutation restart. When
`stop()` itself fails, it closes the messaging boundary, marks the runtime
terminal and rejects all subsequent starts, trust mutations and text staging.
A failed pre-mutation stop aborts before any M2/M3 trust operation. Four JVM
fault-injection tests cover partial start, post-mutation restart, failed
pre-mutation stop and combined start+stop failure with suppressed causality.

This still cannot prove that an underlying native/OEM socket has stopped when
both stop and close fail, nor protect other runtime instances, different
processes or future M5 effects. It is a local fail-closed control improvement,
not permission to activate audio or merge the security Draft.

## Process-local transport lease across acceptance runtimes

The Android runtime factory now uses one process-local WSS gate per canonical
app-private directory. It admits at most one active M4.5 WSS owner in this
process; another runtime cannot start WSS, stage outbound text or mutate
M2/M3 trust while a different runtime owns the transport. Scoped trust
mutations hold the same gate through WSS stop, M2/M3 operations and restart.
A process-wide volatile generation rejects starts queued across another
runtime's trust mutation. Failed stop/close poisons the gate for the lifetime
of the process instead of allowing a second socket to start on uncertain
transport state. Closing a healthy owner releases only its own lease.
Three JVM regressions cover competing runtime admission, queued cross-runtime
start fencing and a poisoned stop; they do not simulate Android process death.

This is **process-only** and cannot claim durable transaction semantics:
WSS asynchronous callbacks, independently stored M2 consent, M3 ratchet and
M5 effect execution do not share an atomic commit, other app processes are
not fenced, and the persisted replay/rollback gaps remain. No media, call
runner, microphone, server or release change is introduced.

## Reentrant socket cancellation and cleanup failure

The M4 WSS coordinator now detaches the active socket and clears authenticated
state **before** calling the socket's external `cancel()`. A synchronous
`onClosed` callback during cancellation can no longer re-enter the coordinator
as if that socket were active and issue a second cancel. Stop also attempts
socket cancellation even when timer cancellation throws; the original failure
is preserved, with subsequent cancellation failures suppressed. The Android
messaging boundary closes the retry scheduler even if WSS stop throws.
Two JVM transport regressions cover synchronous close reentrancy, throwing
cancel, late callback rejection and absence of requeued work. A failed cancel
remains an **uncertain physical shutdown**, so the higher-level process gate
must poison the runtime and never start another transport owner. These tests
are synthetic, not real OkHttp or device teardown proof.
