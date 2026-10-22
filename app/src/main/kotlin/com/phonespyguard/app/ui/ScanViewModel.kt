package com.phonespyguard.app.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.phonespyguard.app.collect.AppFactsCollector
import com.phonespyguard.app.collect.DeviceSettingsCollector
import com.phonespyguard.app.detect.RuleBundleProvider
import com.phonespyguard.app.watch.EvidenceStore
import com.phonespyguard.detection.Confidence
import com.phonespyguard.detection.DetectionEngine
import com.phonespyguard.detection.Verdict
import com.phonespyguard.evidence.EntryType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** What the scan screen shows. */
public sealed interface ScanState {
    public data object Idle : ScanState
    public data object Scanning : ScanState

    /**
     * A finished device scan. [concerns] are the apps worth showing, ordered
     * most concerning first; [appsChecked] and [rulesSkipped] back the honest
     * "what ran" summary the spec requires instead of a bare "you're safe"
     * (FR-CHK-03). [worst] drives which safety guidance leads. [rulesExpired]
     * warns when the bundle is stale (security review M3).
     */
    public data class Done(
        val concerns: List<Verdict>,
        val appsChecked: Int,
        val rulesSkipped: Int,
        val worst: Confidence,
        val rulesExpired: Boolean,
    ) : ScanState
}

public class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow<ScanState>(ScanState.Idle)
    public val state: StateFlow<ScanState> = _state.asStateFlow()

    public fun runScan() {
        if (_state.value is ScanState.Scanning) return
        _state.value = ScanState.Scanning
        viewModelScope.launch {
            _state.value = withContext(Dispatchers.Default) { scan() }
        }
    }

    private fun scan(): ScanState.Done {
        val bundle = RuleBundleProvider.bundle()
        val engine = DetectionEngine(bundle)
        val snapshot = HashMap(AppFactsCollector(getApplication(), bundle.indicators).collect())
        val (deviceSubject, deviceFacts) = DeviceSettingsCollector(getApplication()).collect()
        snapshot[deviceSubject] = deviceFacts

        val concerns = mutableListOf<Verdict>()
        var skipped = 0
        var worst = Confidence.UNLIKELY
        for ((subject, facts) in snapshot) {
            val eval = engine.evaluate(subject, facts)
            skipped += eval.skippedRuleIds.size
            if (eval.verdict.confidence != Confidence.UNLIKELY || eval.verdict.concerning.isNotEmpty()) {
                concerns += eval.verdict
                if (eval.verdict.confidence.ordinal < worst.ordinal) worst = eval.verdict.confidence
            }
        }
        concerns.sortBy { it.confidence.ordinal } // CONFIRMED first

        // Persist the findings so the record survives (security review C3).
        if (concerns.any { it.confidence != Confidence.UNLIKELY }) {
            runCatching {
                EvidenceStore(getApplication()).update { log ->
                    for (v in concerns.filter { it.confidence != Confidence.UNLIKELY }) {
                        log.append(
                            type = EntryType.FINDING,
                            summary = "${v.confidence.name}: ${v.subject}",
                            details = mapOf(
                                "signals" to v.concerning.joinToString(",") { it.ruleId },
                            ),
                        )
                    }
                }
            }
        }

        return ScanState.Done(
            concerns = concerns,
            appsChecked = snapshot.size,
            rulesSkipped = skipped,
            worst = worst,
            rulesExpired = bundle.isExpired(),
        )
    }
}
