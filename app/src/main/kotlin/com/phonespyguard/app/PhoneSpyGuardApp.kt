package com.phonespyguard.app

import android.app.Application
import com.phonespyguard.app.detect.EncryptedBundleStore
import com.phonespyguard.app.detect.RuleBundleProvider
import com.phonespyguard.app.detect.RuleUpdateScheduler
import com.phonespyguard.app.watch.AlertNotifier
import com.phonespyguard.app.watch.ChangeWatchScheduler

/**
 * The application entry point. Sets up the alert channel, lets the rule engine
 * pick up any verified downloaded update, schedules the daily signed-rule-update
 * check and the change watch on first launch; the boot receiver re-arms the
 * watch after a reboot.
 */
public class PhoneSpyGuardApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // A downloaded rule update is applied only after 2-of-3 verification;
        // this just points the provider at where such an update is stored.
        RuleBundleProvider.attachUpdateStore(EncryptedBundleStore(this))
        AlertNotifier(this).ensureChannel()
        ChangeWatchScheduler.schedule(this)
        RuleUpdateScheduler.schedule(this)
    }
}
