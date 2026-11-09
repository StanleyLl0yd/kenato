package com.sl.kenato

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import com.sl.kenato.contact.ExternalInviteLink
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
import com.sl.kenato.call.VoiceCapabilityQrPhotoKind
import com.sl.kenato.ui.theme.KenatoTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private lateinit var acceptance: M45AcceptanceController
    // A bearer invitation received from another app is ephemeral and never enters SavedState.
    private var pendingExternalInvite by mutableStateOf<String?>(null)

    private fun offerExternalInvite(candidate: Intent?) {
        if (candidate?.action != Intent.ACTION_VIEW) return
        // Do not retain an invite bearer token in Activity.getIntent() after parsing.
        pendingExternalInvite = ExternalInviteLink.canonicalOrNull(candidate.dataString)
        setIntent(Intent(this, MainActivity::class.java))
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        offerExternalInvite(intent)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        acceptance = M45AcceptanceController(applicationContext)
        if (savedInstanceState == null) offerExternalInvite(intent)
        setContent {
            KenatoTheme {
                KenatoApp(
                    acceptance,
                    externalInvite = pendingExternalInvite,
                    onExternalInviteConsumed = { pendingExternalInvite = null },
                )
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

private data class VoicePhotoRequest(val kind: VoiceCapabilityQrPhotoKind, val peerId: String? = null)
private data class VoicePhotoSelection(val uri: Uri, val request: VoicePhotoRequest)

@Composable
private fun KenatoApp(
    controller: M45AcceptanceController,
    externalInvite: String?,
    onExternalInviteConsumed: () -> Unit,
) {
    val state = controller.state
    val context = LocalContext.current
    var originInput by rememberSaveable { mutableStateOf(state.serviceOrigin) }
    // Invitations and unsent E2EE drafts must not enter Android SavedState plaintext.
    var inviteInput by remember { mutableStateOf("") }
    // QR visibility is an in-memory UI toggle; the invite is still a one-time bearer token.
    var visibleInviteQr by remember { mutableStateOf<String?>(null) }
    // A draft belongs to exactly one pinned peer, never a different selected contact.
    var messageInput by remember(state.selectedPeerIdentityId) { mutableStateOf("") }
    var selectedScreen by rememberSaveable { mutableStateOf("Chats") }
    // Navigation only: never persist a peer-specific screen or plaintext draft in SavedState.
    var openConversationPeer by remember { mutableStateOf<String?>(null) }
    val screenScroll = rememberScrollState()
    // QR inputs are deliberately not saveable/restored across activity/process recreation.
    var voiceChallengeInput by remember { mutableStateOf("") }
    var voiceProofInput by remember { mutableStateOf("") }
    // The picker is an explicit user action. Its URI/decoded plaintext are never SavedState.
    var requestedVoicePhoto by remember { mutableStateOf<VoicePhotoRequest?>(null) }
    var selectedVoicePhoto by remember { mutableStateOf<VoicePhotoSelection?>(null) }
    var voicePhotoError by remember { mutableStateOf<String?>(null) }
    var invitePhotoError by remember { mutableStateOf<String?>(null) }
    val voicePhotoPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri ->
        val request = requestedVoicePhoto
        requestedVoicePhoto = null
        if (uri != null && request != null) {
            selectedVoicePhoto = VoicePhotoSelection(uri, request)
        }
    }

    // System Back returns to the inbox before leaving the app.
    BackHandler(enabled = selectedScreen != "Chats" || openConversationPeer != null) {
        if (selectedScreen != "Chats") selectedScreen = "Chats"
        openConversationPeer = null
    }

    LaunchedEffect(externalInvite) {
        if (externalInvite != null) {
            // Deliberately do NOT redeem a link automatically: the user must tap Join securely.
            inviteInput = externalInvite
            selectedScreen = "Contacts"
            openConversationPeer = null
            onExternalInviteConsumed()
        }
    }

    LaunchedEffect(state.pendingInvites) {
        if (visibleInviteQr != null && visibleInviteQr !in state.pendingInvites) {
            visibleInviteQr = null
        }
    }

    LaunchedEffect(state.voiceUiEpoch, state.selectedPeerIdentityId) {
        voiceChallengeInput = ""
        voiceProofInput = ""
        voicePhotoError = null
    }

    LaunchedEffect(selectedVoicePhoto) {
        val selection = selectedVoicePhoto ?: return@LaunchedEffect
        try {
            val value = withContext(Dispatchers.IO) {
                VoiceCapabilityQrPhotoReader.read(context, selection.uri, selection.request.kind)
            }
            // Ignore stale picker results after a contact or navigation change.
            val inviteTarget = selection.request.kind == VoiceCapabilityQrPhotoKind.INVITE &&
                selectedScreen == "Contacts"
            val voiceTarget = selection.request.kind != VoiceCapabilityQrPhotoKind.INVITE &&
                controller.state.selectedPeerIdentityId == selection.request.peerId
            if (inviteTarget || voiceTarget) {
                when (selection.request.kind) {
                    VoiceCapabilityQrPhotoKind.INVITE -> {
                        inviteInput = value
                        invitePhotoError = null
                    }
                    VoiceCapabilityQrPhotoKind.CHALLENGE -> voiceChallengeInput = value
                    VoiceCapabilityQrPhotoKind.PROOF -> voiceProofInput = value
                }
                if (voiceTarget) voicePhotoError = null
            }
        } catch (_: Exception) {
            // Never echo malicious QR text or private content-provider URI into UI/logs.
            if (selection.request.kind == VoiceCapabilityQrPhotoKind.INVITE &&
                selectedScreen == "Contacts"
            ) {
                invitePhotoError = "The image does not contain a valid Kenato invitation QR."
            } else if (selection.request.kind != VoiceCapabilityQrPhotoKind.INVITE &&
                controller.state.selectedPeerIdentityId == selection.request.peerId
            ) {
                voicePhotoError = "The selected image has no readable matching Kenato voice QR."
            }
        } finally {
            selectedVoicePhoto = null
        }
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
                        onClick = {
                            selectedScreen = screen
                            if (screen != "Chats") openConversationPeer = null
                        },
                        label = { Text(screen) },
                    )
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
                        TextButton(onClick = {
                            visibleInviteQr = if (visibleInviteQr == invite) null else invite
                        }) {
                            Text(if (visibleInviteQr == invite) "Hide QR" else "Show QR")
                        }
                    }
                    if (visibleInviteQr == invite) {
                        Text(
                            "Scan this on the second phone, then explicitly approve joining there.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        InviteQrImage(invite)
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
                Text("Paste an invite or open an invitation link. Confirm the contact before joining; the first phone finishes pairing.")
                if (state.serviceOrigin.isBlank()) {
                    Text("Set up your HTTPS service connection before joining.")
                    TextButton(onClick = { selectedScreen = "Setup" }) {
                        Text("Open connection setup")
                    }
                }
                OutlinedTextField(
                    value = inviteInput,
                    onValueChange = { inviteInput = it },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !state.busy,
                    minLines = 3,
                    maxLines = 6,
                    label = { Text("Invite URI from the other phone") },
                )
                invitePhotoError?.let { message ->
                    Text(
                        message,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                TextButton(
                    onClick = {
                        requestedVoicePhoto = VoicePhotoRequest(VoiceCapabilityQrPhotoKind.INVITE)
                        invitePhotoError = null
                        voicePhotoPicker.launch("image/*")
                    },
                    enabled = !state.busy,
                ) { Text("Import invitation QR from an image") }
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
                                    if (selected) {
                                        openConversationPeer = contact.peerIdentityId
                                        selectedScreen = "Chats"
                                    } else {
                                        controller.selectContact(contact.peerIdentityId) {
                                            openConversationPeer = contact.peerIdentityId
                                            selectedScreen = "Chats"
                                        }
                                    }
                                },
                                enabled = !state.busy,
                            ) { Text(if (selected) "Open chat" else "Select and open chat") }
                            if (selected) {
                                Text(
                                    "Call approval for this contact is below.",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            } else {
                                TextButton(
                                    onClick = { controller.selectContact(contact.peerIdentityId) },
                                    enabled = !state.busy,
                                ) { Text("Select for call approval") }
                            }
                        }
                    }
                }
            }

            // Voice-v2 approval is contact-specific, not part of first-run setup.
            if (state.selectedPeerIdentityId != null) {
                AcceptanceSection(title = "Call approval for selected contact (calls not yet available)") {
                    Text(
                        "Approve calls only for the selected, independently verified pinned contact. " +
                            "QR/text records are not automatically transmitted and do not start a call.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    voicePhotoError?.let { error ->
                        Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
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
                            Text("Or scan this QR on the other phone:", style = MaterialTheme.typography.bodySmall)
                            VoiceCapabilityQrImage(qr, "Voice capability challenge QR")
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
                        TextButton(
                            onClick = {
                                requestedVoicePhoto = VoicePhotoRequest(
                                    VoiceCapabilityQrPhotoKind.CHALLENGE, peer,
                                )
                                voicePhotoError = null
                                voicePhotoPicker.launch("image/*")
                            },
                            enabled = !state.busy,
                        ) { Text("Import challenge QR from an image") }
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
                            Text("Return this QR to the requesting phone:", style = MaterialTheme.typography.bodySmall)
                            VoiceCapabilityQrImage(proof, "Signed voice capability proof QR")
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
                        TextButton(
                            onClick = {
                                requestedVoicePhoto = VoicePhotoRequest(
                                    VoiceCapabilityQrPhotoKind.PROOF, peer,
                                )
                                voicePhotoError = null
                                voicePhotoPicker.launch("image/*")
                            },
                            enabled = !state.busy,
                        ) { Text("Import signed proof QR from an image") }
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

            }

            }

            if (selectedScreen == "Chats") {
                val opened = openConversationPeer
                if (opened != null && opened == state.selectedPeerIdentityId) {
                    ChatConversationSection(
                        state = state,
                        controller = controller,
                        draft = messageInput,
                        onDraftChange = { messageInput = it },
                        onDraftStaged = { messageInput = "" },
                        onBackToChats = { openConversationPeer = null },
                    )
                } else {
                    ChatInboxSection(
                        state = state,
                        onOpenContact = { peer ->
                            if (peer == state.selectedPeerIdentityId) {
                                openConversationPeer = peer
                            } else {
                                controller.selectContact(peer) {
                                    openConversationPeer = peer
                                }
                            }
                        },
                        onAddContact = { selectedScreen = "Contacts" },
                        onOpenSetup = { selectedScreen = "Setup" },
                    )
                }
            }

            if (selectedScreen == "Setup") {
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
