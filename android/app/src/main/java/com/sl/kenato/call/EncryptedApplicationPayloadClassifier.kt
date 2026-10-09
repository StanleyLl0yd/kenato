package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingPlaintext
import com.sl.kenato.messaging.MessagingProtocol
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.SessionStateCodec

internal class EncryptedApplicationPayloadException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal sealed interface EncryptedApplicationPayload {
    class Text(val plaintext: MessagingPlaintext) : EncryptedApplicationPayload
    class Voice(val signal: VoiceSignalPlaintext) : EncryptedApplicationPayload
}

/**
 * Only classify bytes AFTER an authenticated M3 decrypt. Never infer application kind
 * from untrusted outer routing metadata. Versions 1 and 2 share a canonical initial
 * protobuf field (tag 8); older text decoding must not see version 2 as chat.
 *
 * This is NOT a delivery/ACK boundary. The consumer must atomically retain the M3
 * crypto handoff, durably import into the corresponding text history or voice replay
 * journal, and reconcile that exact type after restart BEFORE ACK/call side effects.
 */
internal object EncryptedApplicationPayloadClassifier {
    fun classify(
        decrypted: ByteArray,
        envelope: MessagingEnvelope,
        receivedAtEpochSeconds: Long,
    ): EncryptedApplicationPayload {
        if (decrypted.size < 2 || decrypted.size > SessionStateCodec.MAX_HANDOFF_PLAINTEXT_BYTES ||
            decrypted[0] != 0x08.toByte()
        ) {
            throw EncryptedApplicationPayloadException("Missing canonical encrypted application discriminator")
        }
        return when (decrypted[1].toInt() and 0xff) {
            1 -> {
                val plaintext = try {
                    MessagingWire.decodePlaintext(decrypted).also {
                        if (!MessagingWire.encodePlaintext(it).contentEquals(decrypted)) {
                            throw EncryptedApplicationPayloadException("Noncanonical M4 chat plaintext")
                        }
                        MessagingProtocol.validateDeliveryContext(envelope, it, receivedAtEpochSeconds)
                    }
                } catch (error: Exception) {
                    throw EncryptedApplicationPayloadException("Invalid authenticated chat plaintext", error)
                }
                EncryptedApplicationPayload.Text(plaintext)
            }
            2 -> {
                val signal = try {
                    MessagingProtocol.validateEnvelope(envelope, receivedAtEpochSeconds)
                    VoiceSignalingWire.decode(
                        decrypted,
                        VoiceSignalEnvelopeBinding(
                            envelope.senderIdentityId,
                            envelope.recipientIdentityId,
                            envelope.messageId,
                            envelope.expiresAtEpochSeconds,
                        ),
                        receivedAtEpochSeconds,
                    )
                } catch (error: Exception) {
                    throw EncryptedApplicationPayloadException("Invalid authenticated voice signal", error)
                }
                EncryptedApplicationPayload.Voice(signal)
            }
            else -> throw EncryptedApplicationPayloadException("Unsupported encrypted application type")
        }
    }
}
