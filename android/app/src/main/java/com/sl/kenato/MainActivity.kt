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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
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
    // Invitations and unsent E2EE drafts must not enter Android SavedState plaintext.
    var inviteInput by remember { mutableStateOf("") }
    // A draft belongs to exactly one pinned peer, never a different selected contact.
    var messageInput by remember(state.selectedPeerIdentityId) { mutableStateOf("") }
    var selectedScreen by rememberSaveable { mutableStateOf("Chats") }
    val screenScroll = rememberScrollState()
    // QR inputs are deliberately not saveable/restored across activity/process recreation.
    var voiceChallengeInput by remember { mutableStateOf("") }
    var voiceProofInput by remember { mutableStateOf("") }

    LaunchedEffect(state.voiceUiEpoch, state.selectedPeerIdentityId) {
        voiceChallengeInput = ""
        voiceProofInput = ""
    }

    LaunchedEffect(state.serviceOrigin) {
        originInput = state.serviceOrigin
    }

    // A long Setup page must not leave Chats or Contacts scrolled to its old offset.
    LaunchedEffect(selectedScreen) {
        screenScroll.scrollTo(0)
    }

    Scaffold { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .then(if (selectedScreen == "Chats") Modifier else Modifier.verticalScroll(screenScroll))
                .padding(16.dp),
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
            // The preview label follows the installed APK, not an old hard-coded release.
            val installedVersion = remember(context) {
                @Suppress("DEPRECATION")
                val info = context.packageManager.getPackageInfo(context.packageName, 0)
                info.versionName ?: "unknown"
            }
            Text(
                text = "Encrypted messaging · v$installedVersion",
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

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                listOf("Chats", "Contacts", "Setup").forEach { screen ->
                    FilterChip(
                        selected = selectedScreen == screen,
                        onClick = { selectedScreen = screen },
                        label = { Text(screen) },
                    )
                }
            }

            if (selectedScreen == "Chats" && (
                    state.serviceOrigin.isBlank() || state.contacts.isEmpty()
                )
            ) {
                AcceptanceSection(title = "Get started") {
                    Text(
                        if (state.serviceOrigin.isBlank()) {
                            "Configure your HTTPS service to begin."
                        } else {
                            "Connect with another Kenato user before sending messages."
                        },
                    )
                    Button(
                        onClick = {
                            selectedScreen = if (state.serviceOrigin.isBlank()) "Setup" else "Contacts"
                        },
                    ) {
                        Text(if (state.serviceOrigin.isBlank()) {
                            "Open setup"
                        } else {
                            "Add a contact"
                        })
                    }
                }
            }

            if (selectedScreen == "Setup") {
            AcceptanceSection(title = "Connection settings") {
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
                    ) {
                        Text("Save")
                    }
                    TextButton(
                        onClick = controller::refresh,
                        enabled = !state.busy,
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

            AcceptanceSection(title = "Your identity") {
                Text(
                    "Set up your local identity and secure messaging in one step.",
                    style = MaterialTheme.typography.bodySmall,
                )
                state.identityId?.let { identityId ->
                    Text("Identity ID", style = MaterialTheme.typography.labelMedium)
                    SelectionContainer {
                        Text(identityId, style = MaterialTheme.typography.bodySmall)
                    }
                }
                Button(
                    onClick = {
                        controller.prepareForAcceptance {
                            selectedScreen = "Contacts"
                        }
                    },
                    enabled = !state.busy && state.serviceOrigin.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (state.identityId == null) "Set up secure messaging" else "Refresh secure setup")
                }
            }

            }

            if (selectedScreen == "Contacts") {
            AcceptanceSection(title = "Invite another device") {
                Text("Create an invitation, share it with the other phone, then finish pairing here after it joins.")
                Button(
                    onClick = controller::createInvite,
                    enabled = !state.busy && state.serviceOrigin.isNotBlank(),
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
                        ) {
                            Text("Copy")
                        }
                        TextButton(
                            onClick = { shareText(context, invite) },
                        ) {
                            Text("Share")
                        }
                    }
                    Button(
                        onClick = { controller.claimAndEstablish(invite) },
                        enabled = !state.busy && state.serviceOrigin.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Finish pairing after other phone joins")
                    }
                }
            }

            AcceptanceSection(title = "Join using invite") {
                Text("On the second phone, paste the invitation and join. Then finish pairing on the first phone.")
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
                    onClick = {
                        controller.redeemAndEstablish(inviteInput) {
                            inviteInput = ""
                        }
                    },
                    enabled = !state.busy &&
                        state.serviceOrigin.isNotBlank() &&
                        inviteInput.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Join securely")
                }
            }

            AcceptanceSection(title = "Contacts") {
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
                            TextButton(
                                onClick = {
                                    if (selected) selectedScreen = "Chats"
                                    else controller.selectContact(contact.peerIdentityId) {
                                        selectedScreen = "Chats"
                                    }
                                },
                                enabled = !state.busy,
                            ) { Text(if (selected) "Open chat" else "Select and open chat") }
                        }
                    }
                }
            }

            }

            if (selectedScreen == "Chats") {
                ChatConversationSection(
                    state = state,
                    controller = controller,
                    draft = messageInput,
                    onDraftChange = { messageInput = it },
                    onDraftStaged = { messageInput = "" },
                    onChangeContact = { selectedScreen = "Contacts" },
                )
            }

            if (selectedScreen == "Setup") {
            AcceptanceSection(title = "Call consent setup (calls not yet available)") {
                Text(
                    "Use only with the selected, independently verified pinned M2 contact. " +
                        "QR/text records are not automatically transmitted and do not start a call.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    if (state.voiceCapabilityConfirmed) {
                        "Voice-v2 signed proof: confirmed for selected contact"
                    } else {
                        "Voice-v2 signed proof: not yet confirmed"
                    },
                    style = MaterialTheme.typography.labelMedium,
                )
                state.selectedPeerIdentityId?.let { peer ->
                    Text("Verify selected peer identity before approving:", style = MaterialTheme.typography.bodySmall)
                    SelectionContainer { Text(peer, style = MaterialTheme.typography.bodySmall) }
                    Button(
                        onClick = controller::issueVoiceCapabilityChallenge,
                        enabled = !state.busy && !state.voiceCapabilityConfirmed,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("1. Issue one-time challenge for this peer") }
                    state.voiceChallengeQr?.let { qr ->
                        Text("Share this challenge with the selected peer (expires in 5 minutes):")
                        SelectionContainer { Text(qr, style = MaterialTheme.typography.bodySmall) }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(onClick = { copyText(context, qr, "Kenato voice challenge") }) { Text("Copy challenge") }
                            TextButton(onClick = { shareText(context, qr) }) { Text("Share") }
                        }
                    }
                    OutlinedTextField(
                        value = voiceChallengeInput,
                        onValueChange = { voiceChallengeInput = it.take(512) },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !state.busy,
                        minLines = 2,
                        maxLines = 5,
                        label = { Text("Challenge received from selected peer") },
                    )
                    Button(
                        onClick = {
                            controller.approveAndSignVoiceCapabilityChallenge(voiceChallengeInput) {
                                voiceChallengeInput = ""
                            }
                        },
                        enabled = !state.busy && voiceChallengeInput.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("2. Verify pinned identity and explicitly approve signing") }
                    state.voiceProofQr?.let { proof ->
                        Text("Share the signed proof back to the requesting peer:")
                        SelectionContainer { Text(proof, style = MaterialTheme.typography.bodySmall) }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(onClick = { copyText(context, proof, "Kenato voice signed proof") }) { Text("Copy proof") }
                            TextButton(onClick = { shareText(context, proof) }) { Text("Share") }
                        }
                    }
                    OutlinedTextField(
                        value = voiceProofInput,
                        onValueChange = { voiceProofInput = it.take(512) },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !state.busy,
                        minLines = 2,
                        maxLines = 5,
                        label = { Text("Signed proof returned by selected peer") },
                    )
                    Button(
                        onClick = {
                            controller.approveAndImportVoiceCapabilityProof(voiceProofInput) {
                                voiceProofInput = ""
                            }
                        },
                        enabled = !state.busy && !state.voiceCapabilityConfirmed && voiceProofInput.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("3. Verify signature and explicitly approve import") }
                } ?: Text("Select a pinned contact to enable offline exchange.")
                Text(
                    "A successful proof does not enable microphone, send signaling or start WebRTC. " +
                        "Do not treat this as a phone-call test.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            AcceptanceSection(title = "Diagnostics") {
                Text(
                    text = "Stored only on this device: timestamps and predefined connection/error codes. " +
                        "No keys, identities, messages, addresses or protocol payloads. " +
                        "Copy/Share sends the journal only when you explicitly choose it.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    text = "Entries: ${state.diagnostics.size} / 128",
                    style = MaterialTheme.typography.labelMedium,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        enabled = !state.busy && state.diagnostics.isNotEmpty(),
                        onClick = { copyText(context, state.diagnostics.joinToString("\n"), "Kenato diagnostics") },
                    ) {
                        Text("Copy log")
                    }
                    Button(
                        enabled = !state.busy && state.diagnostics.isNotEmpty(),
                        onClick = { shareDiagnostics(context, state.diagnostics.joinToString("\n")) },
                    ) {
                        Text("Share")
                    }
                    TextButton(
                        enabled = !state.busy,
                        onClick = controller::clearDiagnostics,
                    ) {
                        Text("Clear")
                    }
                }
                SelectionContainer {
                    Text(
                        text = state.diagnostics.takeLast(40).joinToString("\n").ifBlank { "No diagnostic events yet" },
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            Text(
                text = "Testing note: preserve app data when checking restart and recovery.",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            }
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

private fun copyText(context: Context, value: String, label: String = "Kenato invite") {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
}

private fun shareText(context: Context, value: String) {
    val share = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, value)
    }
    context.startActivity(Intent.createChooser(share, "Share Kenato invite"))
}

private fun shareDiagnostics(context: Context, value: String) {
    // Explicit system chooser only: no background upload and no additional permissions.
    val share = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, value)
    }
    context.startActivity(Intent.createChooser(share, "Share Kenato diagnostics"))
}
