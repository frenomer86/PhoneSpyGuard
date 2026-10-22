package com.phonespyguard.app.ui

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.phonespyguard.app.AppSettings
import com.phonespyguard.app.watch.EvidenceStore
import com.phonespyguard.safety.SafetyPlaybook
import com.phonespyguard.safety.SafetySituation

/**
 * Safety planning, the privacy toggles, and evidence export (FR-SAF, FR-EVD-02,
 * review C4/H1/H7). Everything here is designed for someone who may share a home
 * with the person watching them.
 */
@Composable
public fun SafetyScreen(onQuickExit: () -> Unit) {
    val context = LocalContext.current
    val settings = remember { AppSettings(context) }
    val playbook = remember { SafetyPlaybook.bundled() }

    var alerts by remember { mutableStateOf(settings.alertsEnabled) }
    var discreet by remember { mutableStateOf(settings.discreetMode) }

    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Safety", style = MaterialTheme.typography.headlineSmall)
        OutlinedButton(onClick = onQuickExit) { Text("Quick exit") }

        ToggleRow(
            title = "Background alerts",
            subtitle = "Off is safest. If on, alerts are neutral and are hidden whenever another app could read your notifications.",
            checked = alerts,
        ) { on -> alerts = on; settings.alertsEnabled = on }

        ToggleRow(
            title = "Discreet name and icon",
            subtitle = "Show this app as \"System Services\" with a plain icon.",
            checked = discreet,
        ) { on -> discreet = on; settings.setDiscreetMode(on) }

        AppPinCard()

        Text("Before you change anything", style = MaterialTheme.typography.titleMedium)
        playbook.cardsFor(SafetySituation.BEFORE_REMOVING).forEach { card ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(card.title, fontWeight = FontWeight.Bold)
                    Text(card.body, style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        Text("Your evidence record", style = MaterialTheme.typography.titleMedium)
        Text(
            "Export your timeline to send to the police, a bank or a lawyer. Saving a checkpoint " +
                "somewhere off this phone lets you later prove nothing was deleted.",
            style = MaterialTheme.typography.bodySmall,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { shareEvidence(context) }) { Text("Export evidence") }
            OutlinedButton(onClick = { shareCheckpoint(context) }) { Text("Save a checkpoint") }
        }

        Text("Where to get help", style = MaterialTheme.typography.titleMedium)
        playbook.supportFor(deviceCountry(context)).forEach { r ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(r.name, fontWeight = FontWeight.Bold)
                    Text(r.contact, style = MaterialTheme.typography.bodyMedium)
                    if (r.note.isNotBlank()) Text(r.note, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun AppPinCard() {
    val context = LocalContext.current
    val pinStore = remember { com.phonespyguard.app.security.AppPin(context) }
    var isSet by remember { mutableStateOf(pinStore.isSet()) }
    var entry by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("App PIN", fontWeight = FontWeight.Bold)
            Text(
                "Set a PIN that only unlocks this app. Use it if someone else knows your " +
                    "phone's screen lock. It is separate from your phone PIN.",
                style = MaterialTheme.typography.bodySmall,
            )
            if (isSet) {
                Text("An app PIN is set.", style = MaterialTheme.typography.bodySmall)
                OutlinedButton(onClick = { pinStore.clear(); isSet = false; message = "App PIN removed." }) {
                    Text("Remove app PIN")
                }
            } else {
                androidx.compose.material3.OutlinedTextField(
                    value = entry,
                    onValueChange = { entry = it.filter(Char::isDigit) },
                    label = { Text("New PIN (at least 4 digits)") },
                    singleLine = true,
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword,
                    ),
                )
                OutlinedButton(
                    onClick = {
                        val r = runCatching { pinStore.setPin(entry) }
                        if (r.isSuccess) { isSet = true; entry = ""; message = "App PIN set." } else {
                            message = "PIN must be at least 4 digits."
                        }
                    },
                ) { Text("Set app PIN") }
            }
            if (message.isNotBlank()) Text(message, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun ToggleRow(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.Bold)
                Text(subtitle, style = MaterialTheme.typography.bodySmall)
            }
            Switch(checked = checked, onCheckedChange = onChange)
        }
    }
}

private fun shareEvidence(context: Context) {
    // Share the verifiable bundle as a file via FileProvider, not as inline text:
    // a long chain can exceed the intent size limit, and inline text can land in
    // a messaging app the abuser reads (review N6). The bundle carries the public
    // key and attestation chain so it can be checked off the phone (H7).
    runCatching {
        val dir = File(context.cacheDir, "evidence").apply { mkdirs() }
        val file = File(dir, "phone-spy-guard-evidence.json")
        EvidenceStore(context).writeExportFile(file)
        shareFile(context, file, "Phone Spy Guard — evidence timeline")
    }
}

private fun shareCheckpoint(context: Context) {
    val cp = runCatching {
        val c = EvidenceStore(context).checkpoint()
        "count=${c.count} lastHash=${c.lastHash} at=${c.timestampMillis} keyId=${c.keyId} sig=${c.signature}"
    }.getOrDefault("no evidence yet")
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "Phone Spy Guard — evidence checkpoint")
        putExtra(Intent.EXTRA_TEXT, cp)
    }
    context.startActivity(Intent.createChooser(intent, "Share"))
}

private fun shareFile(context: Context, file: File, subject: String) {
    val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", file)
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "application/json"
        putExtra(Intent.EXTRA_SUBJECT, subject)
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, "Share"))
}

private fun deviceCountry(context: Context): String =
    runCatching { context.resources.configuration.locales[0].country.ifBlank { "INTL" } }
        .getOrDefault("INTL")
