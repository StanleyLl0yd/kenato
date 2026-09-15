package com.sl.kenato.messaging

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString

internal interface MessagingSocket {
    fun connect()
    fun sendBinary(value: ByteArray): Boolean
    fun cancel()
}

internal interface MessagingSocketListener {
    fun onOpen(socket: MessagingSocket)
    fun onBinaryMessage(socket: MessagingSocket, value: ByteArray)
    fun onClosed(socket: MessagingSocket)
    fun onFailure(socket: MessagingSocket, error: Throwable)
}

internal fun interface MessagingSocketFactory {
    /** Creates a dormant socket. No callback may run before [MessagingSocket.connect] is invoked. */
    fun create(url: String, listener: MessagingSocketListener): MessagingSocket
}

/**
 * Thin OkHttp 5 WebSocket adapter. TLS, redirects and certificate validation remain OkHttp/platform
 * defaults; Kenato adds no logging interceptor, trust override, hostname override or parallel HTTP
 * stack here.
 */
internal class OkHttpMessagingSocketFactory(
    private val client: OkHttpClient,
) : MessagingSocketFactory {
    override fun create(url: String, listener: MessagingSocketListener): MessagingSocket =
        OkHttpMessagingSocket(client, Request.Builder().url(url).build(), listener)
}

private class OkHttpMessagingSocket(
    private val client: OkHttpClient,
    private val request: Request,
    private val listener: MessagingSocketListener,
) : MessagingSocket {
    private var delegate: WebSocket? = null
    private var started = false
    private var cancelled = false

    @Synchronized
    override fun connect() {
        if (started || cancelled) return
        started = true
        delegate = client.newWebSocket(
            request,
            object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    listener.onOpen(this@OkHttpMessagingSocket)
                }

                override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                    listener.onBinaryMessage(this@OkHttpMessagingSocket, bytes.toByteArray())
                }

                override fun onMessage(webSocket: WebSocket, text: String) {
                    listener.onFailure(
                        this@OkHttpMessagingSocket,
                        MessagingWssException("M4 WebSocket text frames are forbidden"),
                    )
                    cancel()
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    listener.onClosed(this@OkHttpMessagingSocket)
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    listener.onFailure(this@OkHttpMessagingSocket, t)
                }
            },
        )
        if (cancelled) delegate?.cancel()
    }

    @Synchronized
    override fun sendBinary(value: ByteArray): Boolean {
        if (cancelled || value.isEmpty() || value.size > MESSAGING_MAX_WIRE_FRAME_BYTES) return false
        return delegate?.send(value.toByteString()) == true
    }

    @Synchronized
    override fun cancel() {
        cancelled = true
        delegate?.cancel()
    }
}
