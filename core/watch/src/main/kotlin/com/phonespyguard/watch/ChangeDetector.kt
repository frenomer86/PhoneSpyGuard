package com.phonespyguard.watch

import com.phonespyguard.detection.FactKeys
import com.phonespyguard.detection.FactValue
import com.phonespyguard.detection.Facts

/**
 * A snapshot of the device at one moment: the facts for each subject (keyed by
 * package name, or a device-wide pseudo-subject). The change watcher compares
 * two of these to see what changed since the baseline.
 */
public typealias Snapshot = Map<String, Facts>

/** What changed between two snapshots. */
public enum class ChangeKind {
    /** A subject (app) that was not in the baseline appeared. */
    NEW_APP,

    /** A new app whose install source is sideload/unknown (FR-WCH-02). */
    NEW_SIDELOADED_APP,

    /** A subject present in the baseline is gone. */
    REMOVED_APP,

    /** A surveillance-grade power was switched on after the baseline
     *  (FR-WCH-02, FR-WCH-05). */
    GAINED_POWER,

    /** An app that had a launcher icon stopped showing one (FR-WCH-05). */
    HID_ICON,

    /** An installed app's signing certificate changed on update — how a trusted
     *  app gets swapped for a repackaged, tampered one (security review M2). */
    CERT_CHANGED,
}

/** One detected change, with enough context for an alert and the timeline. */
public data class ChangeEvent(
    val subject: String,
    val kind: ChangeKind,
    val factKey: String? = null,
    val concerning: Boolean,
    val description: String,
)

/**
 * Compares two snapshots and reports what changed (FR-WCH-01/02/05).
 *
 * Pure logic: the Android layer takes a fresh snapshot every 15 minutes and on
 * every install/update, hands the old and new snapshots here, writes the
 * concerning events to the evidence log, and raises an alert that asks the
 * owner "Did you do this?". A change the owner confirms stops raising alerts;
 * that bookkeeping lives above this detector.
 */
public class ChangeDetector(
    /** Boolean facts whose flip to `true` is a newly gained power. */
    private val watchedPowers: List<String> = DEFAULT_WATCHED_POWERS,
) {
    public fun diff(old: Snapshot, new: Snapshot): List<ChangeEvent> {
        val events = mutableListOf<ChangeEvent>()

        for ((subject, newFacts) in new) {
            val oldFacts = old[subject]
            if (oldFacts == null) {
                events += newSubjectEvents(subject, newFacts)
            } else {
                events += changedSubjectEvents(subject, oldFacts, newFacts)
            }
        }

        for (subject in old.keys) {
            if (subject !in new) {
                events += ChangeEvent(
                    subject = subject,
                    kind = ChangeKind.REMOVED_APP,
                    concerning = false,
                    description = "$subject is no longer installed",
                )
            }
        }

        return events
    }

    private fun newSubjectEvents(subject: String, facts: Facts): List<ChangeEvent> {
        val events = mutableListOf<ChangeEvent>()
        val sideloaded = (facts[FactKeys.INSTALL_SOURCE] as? FactValue.Text)?.value in SIDELOAD_SOURCES
        events += ChangeEvent(
            subject = subject,
            kind = if (sideloaded) ChangeKind.NEW_SIDELOADED_APP else ChangeKind.NEW_APP,
            concerning = sideloaded,
            description = if (sideloaded) {
                "$subject was installed from outside an app store"
            } else {
                "$subject was installed"
            },
        )
        // A new app that already holds a watched power is worth flagging too.
        for (power in watchedPowers) {
            if (isOn(facts, power)) {
                events += gainedPower(subject, power)
            }
        }
        return events
    }

    private fun changedSubjectEvents(subject: String, old: Facts, new: Facts): List<ChangeEvent> {
        val events = mutableListOf<ChangeEvent>()
        for (power in watchedPowers) {
            if (!isOn(old, power) && isOn(new, power)) {
                events += gainedPower(subject, power)
            }
        }
        val hadIcon = (old[FactKeys.HAS_LAUNCHER_ICON] as? FactValue.Bool)?.value
        val hasIcon = (new[FactKeys.HAS_LAUNCHER_ICON] as? FactValue.Bool)?.value
        if (hadIcon == true && hasIcon == false) {
            events += ChangeEvent(
                subject = subject,
                kind = ChangeKind.HID_ICON,
                factKey = FactKeys.HAS_LAUNCHER_ICON,
                concerning = true,
                description = "$subject hid its launcher icon",
            )
        }
        val oldCert = (old[FactKeys.CERT_SHA256] as? FactValue.Text)?.value
        val newCert = (new[FactKeys.CERT_SHA256] as? FactValue.Text)?.value
        if (oldCert != null && newCert != null && !oldCert.equals(newCert, ignoreCase = true)) {
            events += ChangeEvent(
                subject = subject,
                kind = ChangeKind.CERT_CHANGED,
                factKey = FactKeys.CERT_SHA256,
                concerning = true,
                description = "$subject was updated and is now signed by someone different",
            )
        }
        return events
    }

    private fun gainedPower(subject: String, power: String) = ChangeEvent(
        subject = subject,
        kind = ChangeKind.GAINED_POWER,
        factKey = power,
        concerning = true,
        description = "$subject gained ${humanPower(power)}",
    )

    private fun isOn(facts: Facts, key: String): Boolean =
        (facts[key] as? FactValue.Bool)?.value == true

    public companion object {
        public val SIDELOAD_SOURCES: Set<String> = setOf("sideload", "unknown")

        public val DEFAULT_WATCHED_POWERS: List<String> = listOf(
            FactKeys.ACCESSIBILITY_ENABLED,
            FactKeys.DEVICE_ADMIN,
            FactKeys.NOTIFICATION_ACCESS,
            FactKeys.USAGE_ACCESS,
            FactKeys.DEFAULT_SMS,
            FactKeys.DEFAULT_DIALER,
            FactKeys.VPN_ACTIVE,
            FactKeys.USER_CERTIFICATE_ADDED,
        )

        private fun humanPower(key: String): String = when (key) {
            FactKeys.ACCESSIBILITY_ENABLED -> "accessibility access (can read your screen)"
            FactKeys.DEVICE_ADMIN -> "device-admin rights (harder to remove)"
            FactKeys.NOTIFICATION_ACCESS -> "notification access (can read your notifications)"
            FactKeys.USAGE_ACCESS -> "usage access (can see which apps you use)"
            FactKeys.DEFAULT_SMS -> "the default SMS role (can read your texts)"
            FactKeys.DEFAULT_DIALER -> "the default dialer role (can see your calls)"
            FactKeys.VPN_ACTIVE -> "a VPN (can route your traffic)"
            FactKeys.USER_CERTIFICATE_ADDED -> "a user certificate (can intercept traffic)"
            else -> "a new power ($key)"
        }
    }
}
