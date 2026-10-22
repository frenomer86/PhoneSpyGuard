package com.phonespyguard.app.detect

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.phonespyguard.app.R

/**
 * Checks once a day for a newer signed rule bundle and installs it if it
 * verifies (market-scan item 2). The download is a plain GET over HTTPS with
 * nothing identifying attached; a tampered or under-signed file is refused and
 * the app keeps the rules it already trusts. The update endpoint is a build-time
 * string resource ([R.string.rule_update_url]); when it is blank the check is a
 * clean no-op, so an offline-only build simply runs on its shipped bundle.
 */
public class RuleUpdateWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val payloadUrl = applicationContext.getString(R.string.rule_update_url).trim()
        val signaturesUrl = applicationContext.getString(R.string.rule_update_sig_url).trim()
        if (payloadUrl.isEmpty() || signaturesUrl.isEmpty()) {
            // No update endpoint configured for this build — nothing to do.
            return Result.success()
        }
        // Installed or Refused are both normal daily outcomes (a refusal just
        // means no newer valid bundle, or a transient network miss); the next
        // day's run checks again, so there is no need to retry within the day.
        // Only an unexpected crash asks WorkManager to retry.
        return runCatching {
            RuleBundleProvider.fetchUpdate(HttpUpdateTransport(), payloadUrl, signaturesUrl)
            Result.success()
        }.getOrDefault(Result.retry())
    }

    public companion object {
        public const val UNIQUE_WORK_NAME: String = "psg_rule_update"
    }
}
