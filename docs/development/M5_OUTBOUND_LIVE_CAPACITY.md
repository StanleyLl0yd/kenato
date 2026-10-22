# M5 outbound voice staging: live WSS queue capacity

Isolated, non-production voice staging now rechecks the shared M4/M5
outbound WSS bound **inside** the serialized M3 handoff builder. The initial
preflight already rejected 32 pending outbound records; the builder previously
rechecked only M3's broader 64-record handoff limit, so competing text
staging could fill the WSS queue in between.

The builder now requires fewer than 32 pending outbound handoffs, in addition
to the 64-record M3 total limit, one-uncompleted-voice rule, message-id
uniqueness, current pinned approval, and crypto binding. A failed admission
returns without creating a deliverable voice handoff.

Two JVM regressions inject concurrent pending M4 text records between
preflight and builder evaluation: at 32 they prevent voice staging; at 31
exactly one voice handoff still fits.

**Limitations:** This check assumes the future production adapter executes
pending-handoff reads and M3 staging under one serialized session owner.
#123 shared process ownership and inter-process locking are not accepted.
The tests use an isolated fake handoff builder and cannot substitute for
Android atomic disk/rollback or physical device acceptance. #116/#87/#88 stay
OPEN. M5 only: no live voice sender, media, microphone, new infrastructure,
release or M6.
