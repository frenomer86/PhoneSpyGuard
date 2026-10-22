package com.phonespyguard.app.detect

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/** Schedules the once-a-day signed rule-update check (market-scan item 2). */
public object RuleUpdateScheduler {

    public fun schedule(context: Context) {
        val request = PeriodicWorkRequestBuilder<RuleUpdateWorker>(1, TimeUnit.DAYS)
            // Only run when there is a network; nothing identifying is sent.
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            RuleUpdateWorker.UNIQUE_WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }
}
