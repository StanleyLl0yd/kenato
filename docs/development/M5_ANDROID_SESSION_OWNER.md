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

## Lazy identity initialization through read-looking entry points

The acceptance facade previously bypassed its process WSS transport lease in
`initializeIdentity()`, `pendingInvites()`, `contacts()` and
`conversation()`. The latter three may call M1 `loadOrCreate()` before
reading state; this can create identity state while a different runtime owns
WSS or after a terminal close. Those facade methods now acquire the same
runtime/process monitors, require an open runtime and refuse cross-owner
access **before any lazy initialization**. JVM regressions verify denied
side effects while another runtime owns WSS, and safe access after release.

This only closes facade entry-point bypasses. Direct factory/store callers,
asynchronous callbacks and other Android processes are not fenced by this
process-local gate. It does not provide a durable shared M2/M3/WSS/effect
transaction or authorize live voice.

## Reentrant retry/fail-close teardown and sticky cancellation failure

The WSS stop fix was not sufficient: retry/timeout/fail-closed paths still
called external `socket.cancel()` while that socket remained active, which
could synchronously invoke `onClosed()` and recursively cancel or queue
retries. All three socket shutdown paths now detach the socket and clear
its authentication/recovery in-memory state before cancelling external
socket/timer objects. Each outstanding timer is attempted even if an earlier
cancel throws; failures are retained without abandoning socket cancellation.

Any uncertain teardown now permanently denies `MessagingWssCoordinator.start()`
for that coordinator, and a subsequent `stop()` reports the sticky failure
so the outer M4.5 transport gate can poison its process-local lease rather
than silently releasing an incompletely stopped transport. Four synthetic
JVM regressions cover recursive close and throwing socket cancellation on
retry and fail-close paths. No OkHttp/native/device timing is proven, and
no durable multi-store M5 ownership is claimed.

## Shared process gate for WSS receive and scheduled callbacks

The Android messaging boundary previously held the M4.5 process gate during
explicit start/stop/send/trust mutations but left OkHttp listener callbacks
and retry/timeout tasks outside it. That allowed an inbound authenticated
M3 ratchet/ACK or timer recovery to interleave with another runtime's M2/M3
trust mutation, despite the shared process-local transport lease.

The boundary now wraps **only the Android-owned** WSS socket listener and
retry scheduler. Each async callback enters the shared per-directory process
monitor before the coordinator monitor (same order as explicit runtime calls).
This covers onOpen/onBinary/onClosed/onFailure and scheduled reconnect,
authentication timeout, ACK/durable retry. Socket and scheduler external
cancellation behavior remains unchanged. Two synthetic JVM concurrent
regressions verify socket and timer callbacks cannot enter while the owner
monitor is held and that cancellation delegates correctly.

**This is still not an interprocess lock or durable M2/M3/WSS/consent/effect
commit.** Callback-to-commit failure windows between independent storage
files, direct factory bypasses, shared identity recovery, other processes and
M5 effects remain open under #116/#87. No production voice/mic/JNI enabled.

## Android controller M1 and voice-consent mutation entrypoints

The acceptance controller previously called `LocalIdentityRepository.loadOrCreate()`
and the manual M5 voice capability challenge/sign/import bridge directly,
outside the runtime's shared process transport gate. Thus a second activity
instance or its QR operations could write M1/M2 capability state while
WSS callbacks or a separate runtime were active. The controller now routes
all four operations through the exact same process gate:
- If its existing acceptance runtime owns WSS, pause/stop WSS, mutate,
  and restart only after the action returns successfully.
- Before a runtime or service origin exists, acquire a standalone shared
  process writer slot; deny an active competing WSS owner and advance
  the trust mutation epoch to fence already queued transport starts.

Explicit QR peer validation happens *inside* this critical section, rather
than pre-validating a contact then waiting for the gate. Three JVM
regressions exercise pause/restart, uncertain stop fail-closed, and
standalone queued-start fencing. This is process-only protection and
does not replace the required durable cross-process consent/M3/WSS/KDL1
effect admission or physical tests under #116 and #87.

## Selected contact TOCTOU at outbound M4 staging

Previously the controller read its selected M2 peer and checked the pin
before entering the M4.5 runtime's transport gate; a separate runtime
could modify M2 trust during that gap, allowing an obsolete peer
selection to reach M3 staging. The controller now passes a peer resolver
into `sendTextSelectingPeer`, which executes pin selection/validation
and M3 staging under the exact same process gate. The existing explicit
`sendText(peer, text)` API also delegates through that gate. A
concurrent synthetic test asserts the resolver cannot run until a
trust mutation completes and that the newly selected peer is staged.

A nullable result from the controller's local-trust helper also can no
longer accidentally invoke its standalone fallback a second time:
runtime selection uses an explicit branch rather than an Elvis
expression. No transport protocol, E2EE ciphertext format, or voice
runtime activation changes. Cross-process pin writers remain blocked
by separate M5 release gates.

## Poisoned WSS callback suppression

Serializing callbacks under the process gate alone did not prevent late
callbacks from running **after** a failed WSS stop poisoned that gate.
An uncertain cancel could therefore have left a stale OkHttp callback
able to attempt inbound M3 recovery or ACK even though new runtime
operations were blocked. Android-created socket callbacks and all retry
tasks now check `processGate.permitsTransportCallbacks()` while holding
the gate, immediately before calling the coordinator. If poisoned, the
callback is discarded without ratchet, ACK, reconnect, or new task.
The standalone synthetic wrapper defaults to a permissive predicate
only for off-production unit probes; actual Android wiring always
supplies the shared poisoned-gate predicate. One JVM regression covers
all four listener methods and the retry scheduler after poison.
No native JNI, cross-process recovery, or M5 effect activation occurs.

## Bound incoming WSS frame lifetime at process gate

The production callback adapter now copies nonempty, bounded wire bytes before
waiting on the shared transport owner; zero/oversized input is passed as an
invalid empty frame to the coordinator's existing fail-closed validator without
making a second oversized allocation. Both callback/scheduler adapters require
an explicit permission predicate at construction, eliminating the old default
that silently bypassed the poisoned-gate rejection. Android passes the process
gate; synthetic tests explicitly allow callbacks. One JVM test checks retained
buffer independence and oversized rejection. No physical or interprocess claim.

## Process-lifetime OS lock for M4.5 Android factory entrypoints

The default Android M1/M2/M3 repository factories **and** the M4.5 acceptance
factory now obtain the same app-private, process-lifetime
`FileChannel.tryLock` lease before admitting its first runtime for a canonical
`noBackupFilesDir`. All later acceptance runtimes in that process reuse the same
gate and held descriptor. Competing Android processes using these **default
factories** fail closed before constructing a conflicting M1/M2/M3 owner or
acceptance runtime. Direct constructors that bypass the factories are not
protected. JVM tests
cover genuine separate-JVM contention/release, shared registry reuse, separate
directories, invalid directories and a symbolic-link lock-path rejection. A lock file is never deleted at close,
so an inode replacement cannot silently split waiting owners. The owner registry
prevents duplicate opens in one JVM: closing a second descriptor for the same
inode may release a different POSIX file lock on some platforms. The adapter
rejects callbacks after a lost lease. The operating system releases the lock
after process death; this alone does not establish safe restart.

This is an **advisory entrypoint exclusion**, not a durable transaction:
direct in-memory M1/M2/M3 constructors, M4 history, M5 semantic state,
M2 revocation, the KDL1 claim ledger, and actual effect execution are not
integrated into a common owner. An Android process can die after one local
store commits and before the others; the lock has no pending-intent journal,
anti-rollback epoch, or idempotent crash replay. Do not infer approval from
host JVM lease tests. Before enabling voice, #116 still requires durable,
cross-store recovery and the independent #118/#170/#174/#175 anti-rollback
and physical #87 gates. Production M4.5 compatibility must be checked on
Android 10/13/14+; no JNI/media/microphone/OCI/release change was made.
