package com.sl.kenato

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.weight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Navigation over pinned contacts only. Does not own a second session, message store or
 * transport. Opening a chat always selects that exact pinned identity in the controller.
 */
@Composable
internal fun ColumnScope.ChatInboxSection(
    state: M45AcceptanceUiState,
    onOpenContact: (String) -> Unit,
    onAddContact: () -> Unit,
    onOpenSetup: () -> Unit,
) {
    Card(modifier = Modifier.weight(1f).fillMaxWidth()) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Chats", style = MaterialTheme.typography.headlineSmall)
            if (state.serviceOrigin.isBlank()) {
                Text("Connect to your Kenato service to start secure messaging.")
                Button(onClick = onOpenSetup) { Text("Set up connection") }
            } else if (state.identityId == null) {
                Text("Complete secure messaging setup before starting a conversation.")
                Button(onClick = onOpenSetup) { Text("Set up secure messaging") }
            } else if (state.contacts.isEmpty()) {
                Text("No conversations yet. Pair with another Kenato user first.")
                Button(onClick = onAddContact) { Text("Add contact") }
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        "${state.contacts.size} pinned ${if (state.contacts.size == 1) "contact" else "contacts"}",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    TextButton(onClick = onAddContact) { Text("Add contact") }
                }
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    itemsIndexed(
                        items = state.contacts,
                        key = { _, contact -> contact.peerIdentityId },
                    ) { index, contact ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(12.dp),
                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(
                                    modifier = Modifier.weight(1f),
                                    verticalArrangement = Arrangement.spacedBy(4.dp),
                                ) {
                                    Text(
                                        "Contact ${index + 1}",
                                        style = MaterialTheme.typography.titleMedium,
                                    )
                                    Text(
                                        "Pinned identity · ${contact.peerIdentityId.take(12)}…",
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                                TextButton(
                                    onClick = { onOpenContact(contact.peerIdentityId) },
                                    enabled = !state.busy,
                                ) { Text("Open") }
                            }
                        }
                    }
                }
            }
        }
    }
}
