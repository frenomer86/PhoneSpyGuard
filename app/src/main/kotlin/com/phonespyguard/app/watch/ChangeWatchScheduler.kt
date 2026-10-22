package com.phonespyguard.app.watch

import android.content.Context
import androidx.work.ExistingPeriodicWorkPolicy
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
}
