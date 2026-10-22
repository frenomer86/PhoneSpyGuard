package com.phonespyguard.app.watch

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.phonespyguard.app.AppSettings
import com.phonespyguard.app.collect.AppFactsCollector
import com.phonespyguard.app.collect.DeviceSettingsCollector
import com.phonespyguard.app.collect.ScreenOffTrafficCollector
import com.phonespyguard.app.detect.RuleBundleProvider
import com.phonespyguard.evidence.EntryType
import com.phonespyguard.watch.ChangeDetector
import com.phonespyguard.watch.WatchGapDetector

/**
 * The 15-minute change watch (FR-WCH-01). Each run:
 *  1. collects a fresh snapshot of installed apps and device settings,
 *  2. records any watch gap since the last run (FR-WCH-04),
 *  3. diffs the snapshot against the stored baseline,
 *  4. appends concerning changes to the persisted, signed, hash-chained evidence
 *     log (security review C3) and raises an alert only if the owner opted in
 *     and it is safe to (security review H1), and
 *  5. saves the new snapshot as the next baseline.
 */
public class ChangeWatchWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val settings = AppSettings(applicationContext)
        val indicators = RuleBundleProvider.bundle().indicators
        val collector = AppFactsCollector(applicationContext, indicators)
        val deviceCollector = DeviceSettingsCollector(applicationContext)
        val baselineStore = BaselineStore(applicationContext)
        val evidenceStore = EvidenceStore(applicationContext)
        val notifier = AlertNotifier(applicationContext)
        val detector = ChangeDetector()

        val now = System.currentTimeMillis()

        // With usage access granted, measure what each app uploaded while the
        // screen was off; otherwise this is empty and the signal stays off (item 6).
        val screenOffBytes = ScreenOffTrafficCollector(applicationContext).collect()

        // The snapshot is the installed apps plus one device-wide subject.
        val current = HashMap(collector.collect(baselineStore.priorCerts(), screenOffBytes))
        val (deviceSubject, deviceFacts) = deviceCollector.collect()
        current[deviceSubject] = deviceFacts

        // First run: just baseline, nothing to compare to yet.
        if (!baselineStore.exists()) {
            baselineStore.save(current)
            settings.lastRunMillis = now
            return Result.success()
        }

        // Record a watch gap if the watcher was stopped for too long (FR-WCH-04).
        val gap = WatchGapDetector().check(settings.lastRunMillis, now)
        val events = detector.diff(baselineStore.load(), current).filter { it.concerning }
        val alertable = events.isNotEmpty()

        // One load-mutate-save under the shared lock, so a concurrent scan on
        // the UI thread cannot clobber these entries (review N3).
        if (gap != null || events.isNotEmpty()) {
            evidenceStore.update { log ->
                if (gap != null) {
                    log.append(
                        type = EntryType.WATCH_GAP,
                        summary = "The background check did not run for a while",
                        details = mapOf(
                            "from" to gap.fromMillis.toString(),
                            "to" to gap.toMillis.toString(),
                        ),
                    )
                }
                for (event in events) {
                    log.append(
                        type = EntryType.CHANGE,
                        summary = event.description,
                        details = buildMap {
                            put("subject", event.subject)
                            put("kind", event.kind.name)
                            event.factKey?.let { put("fact", it) }
                        },
                    )
                }
            }
        }
        // One neutral, opt-in alert at most — details stay inside the app.
        if (alertable) notifier.notifyFindingsWaiting()

        baselineStore.save(current)
        settings.lastRunMillis = now
        return Result.success()
    }

    public companion object {
        public const val UNIQUE_WORK_NAME: String = "psg_change_watch"
    }
}
