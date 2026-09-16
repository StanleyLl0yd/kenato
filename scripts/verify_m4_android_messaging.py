#!/usr/bin/env python3
"""Verify the M4 Android messaging durability/privacy contract cannot drift silently."""

from __future__ import annotations

import sys
from pathlib import Path

errors: list[str] = []


def read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"{path}: unable to read: {error}")
        return ""


def require(path: str, text: str, fragment: str) -> None:
    if fragment not in text:
        errors.append(f"{path}: missing M4 Android messaging policy fragment {fragment!r}")


def forbid(path: str, text: str, fragment: str) -> None:
    if fragment in text:
        errors.append(f"{path}: forbidden M4 Android messaging policy fragment {fragment!r}")


versions = read("gradle/libs.versions.toml")
require("gradle/libs.versions.toml", versions, 'okhttp = "5.5.0"')
require(
    "gradle/libs.versions.toml",
    versions,
    'okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }',
)

build = read("android/app/build.gradle.kts")
require("android/app/build.gradle.kts", build, "implementation(libs.okhttp)")

manifest = read("android/app/src/main/AndroidManifest.xml")
for fragment in (
    'android:allowBackup="false"',
    'android:usesCleartextTraffic="false"',
    'android:fullBackupContent="@xml/backup_rules"',
    'android:dataExtractionRules="@xml/data_extraction_rules"',
):
    require("android/app/src/main/AndroidManifest.xml", manifest, fragment)

backup_rules = read("android/app/src/main/res/xml/backup_rules.xml")
data_rules = read("android/app/src/main/res/xml/data_extraction_rules.xml")
for domain in (
    "root",
    "file",
    "database",
    "sharedpref",
    "external",
    "device_root",
    "device_file",
    "device_database",
    "device_sharedpref",
):
    fragment = f'<exclude domain="{domain}" path="." />'
    require("android/app/src/main/res/xml/backup_rules.xml", backup_rules, fragment)
    require("android/app/src/main/res/xml/data_extraction_rules.xml", data_rules, fragment)
for fragment in ("<cloud-backup>", "<device-transfer>"):
    require("android/app/src/main/res/xml/data_extraction_rules.xml", data_rules, fragment)

history_store = read(
    "android/app/src/main/java/com/sl/kenato/messaging/ConversationHistoryStore.kt",
)
for fragment in (
    "AtomicFile(File(context.applicationContext.noBackupFilesDir, STATE_FILE_NAME))",
    "ConversationHistoryStateCodec.MAX_STATE_BYTES",
    "file.startWrite()",
    "output.fd.sync()",
    "file.finishWrite(output)",
    "file.failWrite(output)",
):
    require(
        "android/app/src/main/java/com/sl/kenato/messaging/ConversationHistoryStore.kt",
        history_store,
        fragment,
    )
for fragment in ("filesDir", "cacheDir", "getExternalFilesDir", "SharedPreferences"):
    forbid(
        "android/app/src/main/java/com/sl/kenato/messaging/ConversationHistoryStore.kt",
        history_store,
        fragment,
    )

history_state = read(
    "android/app/src/main/java/com/sl/kenato/messaging/ConversationHistoryState.kt",
)
for fragment in (
    "const val MAX_STATE_BYTES = 16 * 1024 * 1024",
    "const val MAX_MESSAGES = 4096",
    "const val MAX_MESSAGES_PER_CONVERSATION = 1000",
    "const val MAX_CONVERSATION_BYTES = 4 * 1024 * 1024",
    "const val DELIVERY_STATE_PENDING_ACK = 1",
    "const val DELIVERY_STATE_PENDING_ACCEPTANCE = 2",
    "const val DELIVERY_STATE_ACCEPTED = 3",
    "const val DELIVERY_STATE_EXPIRED = 4",
    "private const val LEGACY_FORMAT_VERSION = 1",
    "private const val FORMAT_VERSION = 2",
    'MessageDigest.getInstance("SHA-256")',
    "MessageDigest.isEqual(actualDigest, expectedDigest)",
):
    require(
        "android/app/src/main/java/com/sl/kenato/messaging/ConversationHistoryState.kt",
        history_state,
        fragment,
    )

history_repository = read(
    "android/app/src/main/java/com/sl/kenato/messaging/ConversationHistoryRepository.kt",
)
for fragment in (
    "fun requireCanAppendOutbound(",
    "fun importInboundPendingAck(",
    "fun importOutboundPendingAcceptance(",
    "fun expireOutboundIfDue(",
    "fun markOutboundAccepted(",
    "fun matchesAuthenticatedInboundEnvelope(",
    "DELIVERY_STATE_PENDING_ACCEPTANCE",
    "DELIVERY_STATE_ACCEPTED",
    "DELIVERY_STATE_EXPIRED",
    "plaintext.expiresAtEpochSeconds <= nowEpochSeconds",
    'MessageDigest.getInstance("SHA-256").digest(encodedEnvelope)',
):
    require(
        "android/app/src/main/java/com/sl/kenato/messaging/ConversationHistoryRepository.kt",
        history_repository,
        fragment,
    )

session_state = read("android/app/src/main/java/com/sl/kenato/session/SessionState.kt")
for fragment in (
    "const val MAX_MESSAGE_HANDOFFS = 64",
    "const val MAX_HANDOFF_PAYLOAD_BYTES = 4 * 1024 * 1024",
    "const val MAX_HANDOFF_PLAINTEXT_BYTES = 32 * 1024",
    "const val MAX_HANDOFF_ENVELOPE_BYTES = 96 * 1024",
    "const val HANDOFF_DIRECTION_OUTBOUND = 1",
    "const val HANDOFF_DIRECTION_INBOUND = 2",
    "private const val LEGACY_FORMAT_VERSION = 1",
    "private const val FORMAT_VERSION = 2",
):
    require("android/app/src/main/java/com/sl/kenato/session/SessionState.kt", session_state, fragment)

session_repository = read(
    "android/app/src/main/java/com/sl/kenato/session/LocalSessionRepository.kt",
)
for fragment in (
    "fun encryptAndStageMessageHandoff(",
    "fun decryptAndStageMessageHandoff(",
    "messageHandoffs = state.messageHandoffs + handoff.copyForState()",
    "fun pendingMessageHandoffs(",
    "fun completeMessageHandoff(",
):
    require(
        "android/app/src/main/java/com/sl/kenato/session/LocalSessionRepository.kt",
        session_repository,
        fragment,
    )

socket_path = "android/app/src/main/java/com/sl/kenato/messaging/MessagingWssSocket.kt"
socket = read(socket_path)
for fragment in (
    "internal class OkHttpMessagingSocketFactory private constructor(",
    "constructor() : this(buildMessagingClient())",
    "OkHttpClient.Builder()",
    ".followRedirects(false)",
    ".followSslRedirects(false)",
    "client.newWebSocket(",
    "MessagingWssException(\"M4 WebSocket text frames are forbidden\")",
    "value.size > MESSAGING_MAX_WIRE_FRAME_BYTES",
):
    require(socket_path, socket, fragment)
for fragment in (
    "HttpLoggingInterceptor",
    "hostnameVerifier",
    "sslSocketFactory",
    "X509TrustManager",
):
    forbid(socket_path, socket, fragment)

wss_path = "android/app/src/main/java/com/sl/kenato/messaging/MessagingWssCoordinator.kt"
wss = read(wss_path)
for fragment in (
    "const val MAX_QUEUED_STAGED_SENDS = 32",
    "const val MAX_RECONNECT_ATTEMPTS = 8",
    "const val MAX_DURABLE_RETRY_ATTEMPTS = 8",
    "const val MAX_ACK_RETRY_ATTEMPTS = 8",
    "const val INITIAL_RECONNECT_DELAY_MILLIS = 1_000L",
    "const val MAX_RECONNECT_DELAY_MILLIS = 30_000L",
    "const val AUTHENTICATION_TIMEOUT_MILLIS = 15_000L",
    "const val SEND_ACCEPTANCE_TIMEOUT_MILLIS = 30_000L",
    'private const val MESSAGING_PATH = "/v1/messaging/ws"',
    'serviceOrigin.scheme != "https"',
    "val receivedAt = nowEpochSeconds()",
    "MessagingProtocol.validateEnvelope(envelope, receivedAt)",
    "inbound.handle(envelope, receivedAt)",
    "recovery.expireOutboundIfDue(",
    "sentThisConnection.contains(key)",
    "ensureSendAcceptanceTimeout(socket)",
    "private var durableRetryAttempts = 0",
    "private var ackRetryAttempts = 0",
    "if (hasDurableWorkInFlight()) retryDurableWork(socket) else retryConnection(socket)",
    "private fun retryDurableWork(socket: MessagingSocket)",
    "private fun scheduleDurableReconnect()",
    "durableRetryAttempts >= MAX_DURABLE_RETRY_ATTEMPTS",
    "if (activeStagedSends == 0)",
    "state == MessagingWssState.AUTHENTICATED && sentThisConnection.isNotEmpty()",
    "private fun handleRetryLater(socket: MessagingSocket, error: MessagingWireError)",
    "recoveredAcksSentThisConnection.any { it.matchesMessageId(messageId) }",
    "private fun scheduleAckRetry(socket: MessagingSocket, messageId: ByteArray)",
    "pendingAckRetryMessageIds.add(MessageIdKey(messageId))",
    "ackRetryAttempts >= MAX_ACK_RETRY_ATTEMPTS",
    "M4 RETRY_LATER does not match in-flight durable work",
):
    require(wss_path, wss, fragment)

inbound = read("android/app/src/main/java/com/sl/kenato/messaging/MessagingInboundDelivery.kt")
for fragment in (
    "receivedAtEpochSeconds: Long",
    "MessagingProtocol.validateEnvelope(envelope, receivedAtEpochSeconds)",
    "MessagingProtocol.validateDeliveryContext(envelope, plaintext, receivedAtEpochSeconds)",
    "history.matchesAuthenticatedInboundEnvelope",
    "history.importInboundPendingAck",
    "sessions.completeInboundMessageHandoff",
):
    require("android/app/src/main/java/com/sl/kenato/messaging/MessagingInboundDelivery.kt", inbound, fragment)
forbid(
    "android/app/src/main/java/com/sl/kenato/messaging/MessagingInboundDelivery.kt",
    inbound,
    "MessagingInboundClock",
)

outbound_path = "android/app/src/main/java/com/sl/kenato/messaging/MessagingOutboundSend.kt"
outbound = read(outbound_path)
for fragment in (
    "outboundSends = coordinator.recoverOutbound(ownerIdentityId)",
    "inboundAcks = emptyList()",
    "internal class WssMessagingOutboundAdmission(",
    "synchronized(wss)",
    "if (wss.currentState() == MessagingWssState.AUTHENTICATED)",
    "recovery.expireOutboundIfDue(",
    "private val admission: MessagingOutboundAdmission",
    "val now = nowEpochSeconds()",
    "admission.terminalizeIfSafe(",
    "if (!terminal) activeStagedSends++",
    "MAX_QUEUED_STAGED_SENDS",
    "history.requireCanAppendOutbound(",
    "sessions.encryptAndStageMessageHandoff(",
    "MessagingProtocol.validateEnvelope(envelope, now)",
    "history.importOutboundPendingAcceptance(",
):
    require(outbound_path, outbound, fragment)
forbid(
    outbound_path,
    outbound,
    "override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan = coordinator.recover(ownerIdentityId)",
)
forbid(
    outbound_path,
    outbound,
    "if (plan.outboundSends.size >= MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS)",
)

recovery_path = "android/app/src/main/java/com/sl/kenato/messaging/MessagingRecoveryCoordinator.kt"
recovery = read(recovery_path)
for fragment in (
    "fun recoverOutbound(",
    "includeInbound = false",
    "if (includeInbound) recoverInbound(ownerIdentityId, handoff)",
    "history.importInboundPendingAck",
    "history.importOutboundPendingAcceptance",
    "val wasExpired = before.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED",
    "history.expireOutboundIfDue(",
    "ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED ->",
    "ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED ->",
    "if (!removed && !wasExpired)",
    "history.markOutboundAccepted",
):
    require(recovery_path, recovery, fragment)

conversation = read("android/app/src/main/java/com/sl/kenato/messaging/MessagingConversationService.kt")
for fragment in (
    "MessagingConversationDeliveryState.PENDING_SEND",
    "MessagingConversationDeliveryState.SENT",
    "MessagingConversationDeliveryState.EXPIRED_UNCONFIRMED",
    "durableWork.flushDurableWork()",
):
    require("android/app/src/main/java/com/sl/kenato/messaging/MessagingConversationService.kt", conversation, fragment)

messaging_dir = Path("android/app/src/main/java/com/sl/kenato/messaging")
for source in sorted(messaging_dir.glob("*.kt")):
    text = read(str(source))
    for fragment in (
        "android.util.Log",
        "Log.",
        "Timber.",
        "println(",
        "printStackTrace(",
        "SavedStateHandle",
        "NotificationCompat",
        "android.app.Notification",
        "ClipboardManager",
        "SharedPreferences",
    ):
        forbid(str(source), text, fragment)

required_tests = {
    "android/app/src/test/java/com/sl/kenato/session/SessionStateV2Test.kt": (
        "class SessionStateV2Test",
    ),
    "android/app/src/test/java/com/sl/kenato/session/LocalSessionHandoffTest.kt": (
        "class LocalSessionHandoffTest",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/ConversationHistoryStateTest.kt": (
        "class ConversationHistoryStateTest",
        "legacyV1HistoryDecodesAndReencodesAsV2",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/ConversationHistoryPruningTest.kt": (
        "class ConversationHistoryPruningTest",
        "pendingOutboundIsNeverPrunedEvenAfterEnvelopeExpiry",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingInboundDeliveryTest.kt": (
        "receiveTimeSnapshotRemainsValidThroughPostDecryptContextCheck",
        "exactExpiryBoundaryFailsBeforeSessionLookupOrDecrypt",
        "cleanupFailureAfterHistoryCommitMakesRetryAckWithoutSecondDecrypt",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingRecoveryCoordinatorTest.kt": (
        "class MessagingRecoveryCoordinatorTest",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingOutboundRecoveryIsolationTest.kt": (
        "outboundOnlyRecoveryLeavesInboundHandoffAndAckStateUntouched",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingOfflineExpiryRecoveryTest.kt": (
        "expiredRecoveredQueueIsTerminalizedOfflineBeforeFreshAdmission",
        "outboundStageUsesOneClockSnapshotAcrossNativeEncryption",
        "authenticatedAdmissionDefersTerminalizationToTransport",
        "staleExpiryPlanTreatsAlreadyAcceptedAndCleanedSendAsTerminal",
        "repeatedExpiryAfterCleanupIsIdempotentlyTerminal",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingWssCoordinatorTest.kt": (
        "authenticatedConnectionReplaysExactDurableSendAndPendingAck",
        "expiredRecoveredSendIsTerminalizedBeforeSocketQueueing",
        "reconnectBackoffIsBoundedAndStopsAfterEightAutomaticRetries",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingWssLiveFlushTest.kt": (
        "flushDurableWorkSendsNewlyStagedEnvelopeOnlyOncePerConnection",
        "expiredNewlyStagedWorkIsTerminalizedWithoutFailingLiveSocket",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingWssSendAcceptanceTimeoutTest.kt": (
        "missingSendAcceptedReconnectsAndReplaysExactEnvelope",
        "missingAcceptanceRetryLoopIsBoundedAndBacksOffAcrossSuccessfulReauth",
        "sendAcceptedCancelsOutstandingAcceptanceWatchdog",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingWssDurableDisconnectRetryTest.kt": (
        "authenticatedDisconnectWithInflightSendPreservesDurableBackoffAcrossReauth",
        "authenticatedNetworkFailureWithInflightSendUsesDurableRetryPath",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingWssRetryBudgetIsolationTest.kt": (
        "ackOnlyDisconnectUsesOrdinaryRetryBudgetAcrossSuccessfulReauth",
        "terminalizedExpiredSendDoesNotConsumeRetryBudgetForNextMessage",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingWssAckRetryTest.kt": (
        "recoveredAckRetryLaterBacksOffOnSameSocketWithoutReconnect",
        "ackRetryLaterStopsAutomaticRetriesAfterEightAttempts",
        "liveDeliveryAckRetryLaterReusesDurableRecoveredAck",
        "uncorrelatedRetryLaterFailsClosed",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingWssSocketPolicyTest.kt": (
        "factoryOwnedClientDoesNotFollowRedirectsOrInstallInterceptors",
    ),
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingConversationServiceTest.kt": (
        "class MessagingConversationServiceTest",
    ),
}
for path, fragments in required_tests.items():
    text = read(path)
    for fragment in fragments:
        require(path, text, fragment)

security_review = read("docs/security/M4_ANDROID_MESSAGING_REVIEW.md")
for fragment in (
    "noBackupFilesDir",
    "1000 messages / 4 MiB",
    "4096 messages / 16 MiB",
    "32 staged outbound sends",
    "outbound-only recovery path",
    "expired offline work",
    "authenticated WSS",
    "30-second send-acceptance watchdog",
    "eight-attempt durable retry budget",
    "bounded ACK retry budget",
    "ACK-only connection loss",
    "terminal expiry",
    "uncorrelated message-specific",
    "server response-queue backpressure",
    "redirects",
    "EXPIRED_UNCONFIRMED",
    "one receive-time snapshot",
    "one stage-time snapshot",
    "plaintext",
    "SavedStateHandle",
):
    require("docs/security/M4_ANDROID_MESSAGING_REVIEW.md", security_review, fragment)

makefile = read("Makefile")
require("Makefile", makefile, "python3 scripts/verify_m4_android_messaging.py")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("M4 Android messaging policy OK")