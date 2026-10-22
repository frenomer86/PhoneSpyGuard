package com.phonespyguard.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.phonespyguard.detection.Confidence
import com.phonespyguard.detection.Verdict
import com.phonespyguard.safety.DetectionOutcome
import com.phonespyguard.safety.SafetyAdvisor

/**
 * The device-check screen. It never claims the phone is "safe": it says what was
 * checked, what was found, and what could not run (FR-CHK-03). When something is
 * found it leads with safety guidance — "removal can tip them off", "save the
 * evidence first" — before any removal step (review C4).
 */
@Composable
public fun ScanScreen(viewModel: ScanViewModel, onQuickExit: () -> Unit) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Device check", style = MaterialTheme.typography.headlineSmall)
            OutlinedButton(onClick = onQuickExit) { Text("Quick exit") }
        }
        Text(
            "Check who else can see your device. Nothing leaves your phone unless you export it.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(onClick = viewModel::runScan, modifier = Modifier.fillMaxWidth()) {
            Text("Run device check")
        }

        when (val s = state) {
            is ScanState.Idle -> Unit
            is ScanState.Scanning -> Text("Checking…")
            is ScanState.Done -> ScanResults(s)
        }
    }
}

@Composable
private fun ScanResults(done: ScanState.Done) {
    if (done.rulesExpired) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Text(
                "These detection rules are out of date, so this check may miss newer threats. " +
                    "Connect to the internet to update them.",
                modifier = Modifier.padding(12.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
    Text(
        "Checked ${done.appsChecked} items." +
            if (done.rulesSkipped > 0) " ${done.rulesSkipped} checks could not run." else "",
        style = MaterialTheme.typography.bodySmall,
    )

    // Safety guidance first when something concerning turned up (review C4).
    if (done.worst != Confidence.UNLIKELY) {
        SafetyGuidanceCards(done.worst)
    }

    if (done.concerns.isEmpty()) {
        Text("No apps stood out in this check.", style = MaterialTheme.typography.bodyMedium)
        return
    }
    done.concerns.forEach { VerdictCard(it) }
}

@Composable
private fun SafetyGuidanceCards(worst: Confidence) {
    val advisor = remember { SafetyAdvisor() }
    val outcome = when (worst) {
        Confidence.CONFIRMED -> DetectionOutcome.CONFIRMED
        Confidence.VERY_LIKELY -> DetectionOutcome.VERY_LIKELY
        Confidence.POSSIBLE -> DetectionOutcome.POSSIBLE
        Confidence.UNLIKELY -> DetectionOutcome.NONE
    }
    advisor.forDeviceOutcome(outcome).take(3).forEach { card ->
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(card.title, fontWeight = FontWeight.Bold)
                Text(card.body, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun VerdictCard(verdict: Verdict) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(confidenceLabel(verdict.confidence), fontWeight = FontWeight.Bold)
            Text(verdict.subject, style = MaterialTheme.typography.bodySmall)
            verdict.concerning.forEach { signal ->
                Text("• ${signal.title}", style = MaterialTheme.typography.bodySmall)
            }
            if (verdict.innocentExplanations.isNotEmpty()) {
                Text(
                    "Checked for an innocent explanation: " +
                        verdict.innocentExplanations.joinToString { it.title },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

private fun confidenceLabel(confidence: Confidence): String = when (confidence) {
    Confidence.CONFIRMED -> "Confirmed spying"
    Confidence.VERY_LIKELY -> "Very likely spying"
    Confidence.POSSIBLE -> "Possible — worth a look"
    Confidence.UNLIKELY -> "Unlikely"
}
