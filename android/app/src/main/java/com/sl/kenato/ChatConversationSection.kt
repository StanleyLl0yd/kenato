package com.sl.kenato

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.sl.kenato.messaging.MessagingConversationDeliveryState
import com.sl.kenato.messaging.MessagingConversationDirection
import com.sl.kenato.messaging.MessagingWssState
import java.text.DateFormat
import java.util.Date

/**
 * A real conversation surface over the existing M4 durable E2EE text service.
 * No voice or media is activated here; do not invent recipient-delivery receipts.
 */
@Composable
internal fun ColumnScope.ChatConversationSection(
    state: M45AcceptanceUiState,
    controller: M45AcceptanceController,
    draft: String,
    onDraftChange: (String) -> Unit,
    onDraftStaged: () -> Unit,
    onChangeContact: () -> Unit,
) {
    val peer = state.selectedPeerIdentityId
    val listState = rememberLazyListState()
    LaunchedEffect(peer, state.messages.lastOrNull()?.messageId) {
        if (state.messages.isNotEmpty()) {
            listState.scrollToItem(state.messages.lastIndex)
        }
    }

    Card(modifier = Modifier.fillMaxWidth().weight(1f)) {
        Column(
            modifier = Modifier.fillMaxSize().padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    if (peer == null) "Choose a conversation" else "Chat · ${peer.take(12)}…",
                    style = MaterialTheme.typography.titleMedium,
                )
                TextButton(onClick = onChangeContact) {
                    Text(if (peer == null) "Contacts" else "Change")
                }
            }

            val connection = when (state.messagingState) {
                MessagingWssState.STOPPED -> "Offline"
                MessagingWssState.AUTHENTICATED -> "Connected"
                MessagingWssState.FAILED -> "Connection error"
                MessagingWssState.RETRY_WAIT -> "Reconnecting"
                else -> "Connecting"
            }
            Text(connection, style = MaterialTheme.typography.bodySmall)
            when (state.messagingState) {
                MessagingWssState.STOPPED, MessagingWssState.FAILED -> Button(
                    onClick = controller::startMessaging,
                    enabled = !state.busy && state.identityId != null &&
                        state.serviceOrigin.isNotBlank(),
                ) { Text("Connect") }
                MessagingWssState.AUTHENTICATED -> TextButton(
                    onClick = controller::stopMessaging,
                    enabled = !state.busy,
                ) { Text("Disconnect") }
                else -> TextButton(
                    onClick = controller::stopMessaging,
                    enabled = !state.busy,
                ) { Text("Cancel connection") }
            }

            if (peer == null) {
                Box(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        "Add and verify a contact to exchange encrypted messages.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                Button(onClick = onChangeContact, modifier = Modifier.fillMaxWidth()) {
                    Text("Add a contact")
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    state = listState,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    contentPadding = PaddingValues(vertical = 8.dp),
                ) {
                    if (state.messages.isEmpty()) {
                        item {
                            Text(
                                "No messages yet. Start the conversation below.",
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }
                    items(state.messages, key = { it.messageId }) { message ->
                        val outgoing = message.direction == MessagingConversationDirection.OUTBOUND
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = if (outgoing) Arrangement.End else Arrangement.Start,
                        ) {
                            Card(
                                modifier = Modifier.widthIn(max = 320.dp),
                                colors = CardDefaults.cardColors(
                                    containerColor = if (outgoing) {
                                        MaterialTheme.colorScheme.primaryContainer
                                    } else {
                                        MaterialTheme.colorScheme.surfaceVariant
                                    },
                                ),
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp),
                                ) {
                                    SelectionContainer {
                                        Text(message.text, style = MaterialTheme.typography.bodyLarge)
                                    }
                                    val time = DateFormat.getDateTimeInstance(
                                        DateFormat.SHORT, DateFormat.SHORT,
                                    ).format(Date(message.sentAtEpochSeconds * 1000L))
                                    val status = when (message.deliveryState) {
                                        MessagingConversationDeliveryState.RECEIVED -> "Received"
                                        MessagingConversationDeliveryState.PENDING_SEND -> "Waiting to send"
                                        // Relay acceptance is NOT recipient delivery or read.
                                        MessagingConversationDeliveryState.SENT -> "Accepted by server"
                                        MessagingConversationDeliveryState.EXPIRED_UNCONFIRMED ->
                                            "Delivery unconfirmed · expired"
                                    }
                                    Text(
                                        if (outgoing) "$status · $time" else time,
                                        style = MaterialTheme.typography.labelSmall,
                                    )
                                }
                            }
                        }
                    }
                }
                OutlinedTextField(
                    value = draft,
                    onValueChange = onDraftChange,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !state.busy,
                    maxLines = 4,
                    label = { Text("Encrypted message") },
                )
                Button(
                    onClick = { controller.sendText(draft) { onDraftStaged() } },
                    enabled = !state.busy && draft.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Send")
                }
            }
        }
    }
}
