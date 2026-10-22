package com.phonespyguard.app.watch

import android.content.Context
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/** Schedules the periodic change watch (FR-WCH-01, NFR-REL-02). */
public object ChangeWatchScheduler {

    public fun schedule(context: Context) {
        val request = PeriodicWorkRequestBuilder<ChangeWatchWorker>(15, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            ChangeWatchWorker.UNIQUE_WORK_NAME,
            // KEEP so a reboot or app update does not reset the cadence, but the
            // watch still resumes if it was never scheduled.
            ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }

    /**
     * Runs one change-watch scan as soon as the OS allows, instead of waiting for
     * the next 15-minute tick (market-scan item 5). Fired by [PackageChangeReceiver]
     * when an app is installed or replaced, so a freshly planted app is examined
     * within moments where the device delivers the package broadcast. A burst of
     * installs coalesces into one scan (KEEP), and the periodic watch remains the
     * guaranteed fallback on devices that throttle the broadcast.
     */
    public fun scanNow(context: Context) {
        val request = OneTimeWorkRequestBuilder<ChangeWatchWorker>()
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            SCAN_NOW_WORK_NAME,
            ExistingWorkPolicy.KEEP,
            request,
        )
    }

    private const val SCAN_NOW_WORK_NAME: String = "psg_change_watch_now"
}
