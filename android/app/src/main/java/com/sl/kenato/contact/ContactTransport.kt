package com.sl.kenato.contact

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI

internal interface ContactTransport {
    fun publishIdentity(bundle: M2PublicIdentityBundle): Long

    fun createInvite(invite: M2InviteDescriptor): Long

    fun redeemInvite(
        invite: M2InviteDescriptor,
        redeemerBundle: M2PublicIdentityBundle,
        redemptionSignature: ByteArray,
    ): RedeemInviteWireResponse

    fun claimInvite(
        creatorIdentityId: ByteArray,
        token: ByteArray,
        claimSignature: ByteArray,
    ): ClaimInviteWireResponse
}

internal class ContactTransportException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal class HttpContactTransport(baseUri: URI) : ContactTransport {
    private val origin = validateOrigin(baseUri)

    override fun publishIdentity(bundle: M2PublicIdentityBundle): Long {
        val response = post(
            path = "/v1/identity/publish",
            body = ContactWire.encodePublishIdentityRequest(bundle),
            expectedStatus = HttpURLConnection.HTTP_OK,
        )
        return ContactWire.decodePublishIdentityResponse(response).acceptedRevision
    }

    override fun createInvite(invite: M2InviteDescriptor): Long {
        val response = post(
            path = "/v1/invites",
            body = ContactWire.encodeCreateInviteRequest(invite),
            expectedStatus = HttpURLConnection.HTTP_CREATED,
        )
        return ContactWire.decodeCreateInviteResponse(response).expiresAtEpochSeconds
    }

    override fun redeemInvite(
        invite: M2InviteDescriptor,
        redeemerBundle: M2PublicIdentityBundle,
        redemptionSignature: ByteArray,
    ): RedeemInviteWireResponse = ContactWire.decodeRedeemInviteResponse(
        post(
            path = "/v1/invites/redeem",
            body = ContactWire.encodeRedeemInviteRequest(invite, redeemerBundle, redemptionSignature),
            expectedStatus = HttpURLConnection.HTTP_OK,
        ),
    )

    override fun claimInvite(
        creatorIdentityId: ByteArray,
        token: ByteArray,
        claimSignature: ByteArray,
    ): ClaimInviteWireResponse = ContactWire.decodeClaimInviteResponse(
        post(
            path = "/v1/invites/claim",
            body = ContactWire.encodeClaimInviteRequest(creatorIdentityId, token, claimSignature),
            expectedStatus = HttpURLConnection.HTTP_OK,
        ),
    )

    private fun post(path: String, body: ByteArray, expectedStatus: Int): ByteArray {
        if (body.isEmpty() || body.size > MAX_CONTACT_WIRE_BYTES) {
            throw ContactTransportException("Contact request size is invalid")
        }
        val connection = try {
            origin.resolve(path).toURL().openConnection() as HttpURLConnection
        } catch (error: Exception) {
            throw ContactTransportException("Unable to open contact service connection", error)
        }
        try {
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.doInput = true
            connection.doOutput = true
            connection.connectTimeout = CONNECT_TIMEOUT_MILLIS
            connection.readTimeout = READ_TIMEOUT_MILLIS
            connection.setFixedLengthStreamingMode(body.size)
            connection.setRequestProperty("Content-Type", PROTOBUF_CONTENT_TYPE)
            connection.setRequestProperty("Accept", PROTOBUF_CONTENT_TYPE)
            connection.setRequestProperty("Cache-Control", "no-store")
            connection.setRequestProperty("User-Agent", "Kenato")
            connection.outputStream.use { it.write(body) }

            val status = connection.responseCode
            if (status != expectedStatus) {
                throw ContactTransportException("Contact service rejected the request (HTTP $status)")
            }
            val contentType = connection.getHeaderField("Content-Type")
                ?.substringBefore(';')
                ?.trim()
                ?.lowercase()
            if (contentType != PROTOBUF_CONTENT_TYPE && contentType != ALTERNATE_PROTOBUF_CONTENT_TYPE) {
                throw ContactTransportException("Contact service returned an unexpected content type")
            }
            val length = connection.contentLengthLong
            if (length > MAX_CONTACT_WIRE_BYTES) {
                throw ContactTransportException("Contact response is too large")
            }
            return readBounded(connection.inputStream)
        } catch (error: ContactTransportException) {
            throw error
        } catch (error: Exception) {
            throw ContactTransportException("Contact service request failed", error)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: InputStream): ByteArray = input.use { stream ->
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(4 * 1024)
        var total = 0
        while (true) {
            val count = stream.read(buffer)
            if (count < 0) break
            total += count
            if (total > MAX_CONTACT_WIRE_BYTES) {
                throw ContactTransportException("Contact response is too large")
            }
            output.write(buffer, 0, count)
        }
        output.toByteArray().also {
            if (it.isEmpty()) throw ContactTransportException("Contact response is empty")
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MILLIS = 5_000
        const val READ_TIMEOUT_MILLIS = 10_000
        const val PROTOBUF_CONTENT_TYPE = "application/x-protobuf"
        const val ALTERNATE_PROTOBUF_CONTENT_TYPE = "application/protobuf"

        fun validateOrigin(uri: URI): URI {
            if (
                uri.scheme != "https" ||
                uri.host.isNullOrBlank() ||
                uri.rawUserInfo != null ||
                uri.rawQuery != null ||
                uri.rawFragment != null ||
                (uri.rawPath.isNotEmpty() && uri.rawPath != "/")
            ) {
                throw ContactTransportException("Contact service origin must be an HTTPS origin")
            }
            return URI("https", null, uri.host, uri.port, "/", null, null)
        }
    }
}
