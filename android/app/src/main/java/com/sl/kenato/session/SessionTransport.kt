package com.sl.kenato.session

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI

internal interface SessionTransport {
    fun publishBootstrap(bundle: SessionBootstrapBundle): SessionPublishWireResponse

    fun reserveBootstrap(
        creatorIdentityId: ByteArray,
        redeemerIdentityId: ByteArray,
        inviteToken: ByteArray,
        reserveSignature: ByteArray,
    ): SessionReserveWireResponse

    fun submitInit(request: SessionSubmitInit)

    fun claimInit(
        creatorIdentityId: ByteArray,
        inviteToken: ByteArray,
        claimSignature: ByteArray,
    ): SessionClaimWireResponse
}

internal class SessionTransportException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal class HttpSessionTransport(baseUri: URI) : SessionTransport {
    private val origin = validateOrigin(baseUri)

    override fun publishBootstrap(bundle: SessionBootstrapBundle): SessionPublishWireResponse =
        SessionWire.decodePublishBootstrapResponse(
            post(
                path = "/v1/session/bootstrap/publish",
                body = SessionWire.encodePublishBootstrapRequest(bundle),
            ),
        )

    override fun reserveBootstrap(
        creatorIdentityId: ByteArray,
        redeemerIdentityId: ByteArray,
        inviteToken: ByteArray,
        reserveSignature: ByteArray,
    ): SessionReserveWireResponse = SessionWire.decodeReserveBootstrapResponse(
        post(
            path = "/v1/session/bootstrap/reserve",
            body = SessionWire.encodeReserveBootstrapRequest(
                creatorIdentityId,
                redeemerIdentityId,
                inviteToken,
                reserveSignature,
            ),
        ),
    )

    override fun submitInit(request: SessionSubmitInit) {
        SessionWire.decodeSubmitInitResponse(
            post(
                path = "/v1/session/init",
                body = SessionWire.encodeSubmitInitRequest(request),
            ),
        )
    }

    override fun claimInit(
        creatorIdentityId: ByteArray,
        inviteToken: ByteArray,
        claimSignature: ByteArray,
    ): SessionClaimWireResponse = SessionWire.decodeClaimInitResponse(
        post(
            path = "/v1/session/init/claim",
            body = SessionWire.encodeClaimInitRequest(creatorIdentityId, inviteToken, claimSignature),
        ),
    )

    private fun post(path: String, body: ByteArray): ByteArray {
        if (body.isEmpty() || body.size > SESSION_MAX_WIRE_BYTES) {
            throw SessionTransportException("M3 session request size is invalid")
        }
        val connection = try {
            origin.resolve(path).toURL().openConnection() as HttpURLConnection
        } catch (error: Exception) {
            throw SessionTransportException("Unable to open M3 session service connection", error)
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
            if (status != HttpURLConnection.HTTP_OK) {
                throw SessionTransportException("M3 session service rejected the request (HTTP $status)")
            }
            val contentType = connection.getHeaderField("Content-Type")
                ?.substringBefore(';')
                ?.trim()
                ?.lowercase()
            if (contentType != PROTOBUF_CONTENT_TYPE && contentType != ALTERNATE_PROTOBUF_CONTENT_TYPE) {
                throw SessionTransportException("M3 session service returned an unexpected content type")
            }
            val length = connection.contentLengthLong
            if (length > SESSION_MAX_WIRE_BYTES) {
                throw SessionTransportException("M3 session response is too large")
            }
            return readBounded(connection.inputStream)
        } catch (error: SessionTransportException) {
            throw error
        } catch (error: Exception) {
            throw SessionTransportException("M3 session service request failed", error)
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
            if (total > SESSION_MAX_WIRE_BYTES) {
                throw SessionTransportException("M3 session response is too large")
            }
            output.write(buffer, 0, count)
        }
        output.toByteArray().also {
            if (it.isEmpty()) throw SessionTransportException("M3 session response is empty")
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
                throw SessionTransportException("M3 session service origin must be an HTTPS origin")
            }
            return URI("https", null, uri.host, uri.port, "/", null, null)
        }
    }
}
