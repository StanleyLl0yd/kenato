package com.sl.kenato

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.weight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sl.kenato.messaging.MessagingConversationDirection
import com.sl.kenato.ui.theme.KenatoTheme

class MainActivity : ComponentActivity() {
    private lateinit var acceptance: M45AcceptanceController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        acceptance = M45AcceptanceController(applicationContext)
        setContent {
            KenatoTheme {
                KenatoApp(acceptance)
            }
        }
    }

    override fun onStart() {
        super.onStart()
        acceptance.onAppForeground()
    }

    override fun onStop() {
        acceptance.onAppBackground()
        super.onStop()
    }

    override fun onDestroy() {
        acceptance.close()
        super.onDestroy()
    }
}

@Composable
private fun KenatoApp(controller: M45AcceptanceController) {
    val state = controller.state
    val context = LocalContext.current
    var originInput by rememberSaveable { mutableStateOf(state.serviceOrigin) }
    var inviteInput by rememberSaveable { mutableStateOf("") }
    var messageInput by rememberSaveable { mutableStateOf("") }

    LaunchedEffect(state.serviceOrigin) {
        originInput = state.serviceOrigin
    }

    Scaffold { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.headlineLarge,
            )
            Text(
                text = stringResource(R.string.tagline),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = "M4.5 physical acceptance · 0.0.2",
                style = MaterialTheme.typography.labelLarge,
            )

            state.notice?.let {
                Text(
                    text = it,
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            state.error?.let {
                Text(
                    text = it,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            AcceptanceSection(title = "1. Service") {
                OutlinedTextField(
                    value = originInput,
                    onValueChange = { originInput = it },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !state.busy,
                    singleLine = true,
                    label = { Text("HTTPS service origin") },
                    supportingText = { Text("Example: https://kenato.example.com") },
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = { controller.saveServiceOrigin(originInput) },
                        enabled = !state.busy && originInput.isNotBlank(),
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Save")
                    }
                    TextButton(
                        onClick = controller::refresh,
                        enabled = !state.busy,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Refresh")
                    }
                }
                Text(
                    text = if (state.serviceOrigin.isBlank()) {
                        "No endpoint configured"
                    } else {
                        "Saved: ${state.serviceOrigin}"
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            AcceptanceSection(title = "2. Local identity") {
                Button(
                    onClick = controller::initializeIdentity,
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (state.identityId == null) "Create identity" else "Verify persisted identity")
                }
                state.identityId?.let { identityId ->
                    Text("Identity ID", style = MaterialTheme.typography.labelMedium)
                    SelectionContainer {
                        Text(identityId, style = MaterialTheme.typography.bodySmall)
                    }
                }
                Button(
                    onClick = controller::prepareForAcceptance,
                    enabled = !state.busy && state.identityId != null && state.serviceOrigin.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Publish identity + M3 bootstrap")
                }
            }

            AcceptanceSection(title = "3A. Invite creator") {
                Button(
                    onClick = controller::createInvite,
                    enabled = !state.busy && state.identityId != null && state.serviceOrigin.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Create invite")
                }
                if (state.pendingInvites.isEmpty()) {
                    Text("No pending invites", style = MaterialTheme.typography.bodySmall)
                }
                state.pendingInvites.forEachIndexed { index, invite ->
                    Text("Pending invite ${index + 1}", style = MaterialTheme.typography.labelMedium)
                    SelectionContainer {
                        Text(invite, style = MaterialTheme.typography.bodySmall)
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        TextButton(
                            onClick = { copyText(context, invite) },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text("Copy")
                        }
                        TextButton(
                            onClick = { shareText(context, invite) },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text("Share")
                        }
                    }
                    Button(
                        onClick = { controller.claimAndEstablish(invite) },
                        enabled = !state.busy && state.serviceOrigin.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Claim after peer redeems")
                    }
                }
            }

            AcceptanceSection(title = "3B. Invite redeemer") {
                OutlinedTextField(
                    value = inviteInput,
                    onValueChange = { inviteInput = it },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !state.busy,
                    minLines = 3,
                    maxLines = 6,
                    label = { Text("Invite URI from the other phone") },
                )
                Button(
                    onClick = { controller.redeemAndEstablish(inviteInput) },
                    enabled = !state.busy &&
                        state.identityId != null &&
                        state.serviceOrigin.isNotBlank() &&
                        inviteInput.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Redeem + establish outbound M3 session")
                }
            }

            AcceptanceSection(title = "4. Pinned contacts") {
                if (state.contacts.isEmpty()) {
                    Text("No pinned contacts yet", style = MaterialTheme.typography.bodySmall)
                }
                state.contacts.forEach { contact ->
                    val selected = contact.peerIdentityId == state.selectedPeerIdentityId
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            Text(
                                text = if (selected) "Selected contact" else "Pinned contact",
                                style = MaterialTheme.typography.labelLarge,
                            )
                            SelectionContainer {
                                Text(contact.peerIdentityId, style = MaterialTheme.typography.bodySmall)
                            }
                            Text(
                                text = "Local contact: ${contact.localId}",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            if (!selected) {
                                TextButton(
                                    onClick = { controller.selectContact(contact.peerIdentityId) },
                                    enabled = !state.busy,
                                ) {
                                    Text("Use for messaging")
                                }
                            }
                        }
                    }
                }
            }

            AcceptanceSection(title = "5. M4 messaging") {
                Text(
                    text = "Transport: ${state.messagingState.name}",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = if (state.messagingEnabled) {
                        "Auto-reconnect on next foreground/relaunch is enabled"
                    } else {
                        "Auto-reconnect is disabled"
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = controller::startMessaging,
                        enabled = !state.busy &&
                            state.identityId != null &&
                            state.serviceOrigin.isNotBlank(),
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Connect")
                    }
                    Button(
                        onClick = controller::stopMessaging,
                        enabled = !state.busy,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Disconnect")
                    }
                }

                state.selectedPeerIdentityId?.let { peer ->
                    Text("Peer", style = MaterialTheme.typography.labelMedium)
                    SelectionContainer {
                        Text(peer, style = MaterialTheme.typography.bodySmall)
                    }
                    OutlinedTextField(
                        value = messageInput,
                        onValueChange = { messageInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !state.busy,
                        minLines = 2,
                        maxLines = 5,
                        label = { Text("Message") },
                    )
                    Button(
                        onClick = {
                            controller.sendText(messageInput)
                            messageInput = ""
                        },
                        enabled = !state.busy && messageInput.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Send durable E2EE text")
                    }
                } ?: Text("Select a pinned contact first", style = MaterialTheme.typography.bodySmall)

                HorizontalDivider()

                if (state.messages.isEmpty()) {
                    Text("No durable messages for this contact", style = MaterialTheme.typography.bodySmall)
                }
                state.messages.forEach { message ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            val direction = if (message.direction == MessagingConversationDirection.OUTBOUND) {
                                "OUT"
                            } else {
                                "IN"
                            }
                            Text(
                                text = "$direction · ${message.deliveryState.name}",
                                style = MaterialTheme.typography.labelMedium,
                            )
                            Text(message.text, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                text = "sent=${message.sentAtEpochSeconds} · id=${message.messageId}",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
            }

            Text(
                text = "Acceptance rule: do not reset app data between restart/reboot checks.",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun AcceptanceSection(
    title: String,
    content: @Composable () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

private fun copyText(context: Context, value: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("Kenato invite", value))
}

private fun shareText(context: Context, value: String) {
    val share = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, value)
    }
    context.startActivity(Intent.createChooser(share, "Share Kenato invite"))
}
