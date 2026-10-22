package com.phonespyguard.detection

/**
 * A single fact read from the device by a collector.
 *
 * Facts are the *only* thing a rule can inspect. Collectors (the Android-side
 * code added in Phase 1) turn the device state into these typed values; the
 * detection engine never touches the Android framework itself. Keeping the
 * engine fact-driven is what lets it run unchanged on the JVM, in tests, and
 * later alongside the Rust desktop core against one shared scoring spec.
 */
public sealed interface FactValue {
    public data class Text(val value: String) : FactValue
    public data class Bool(val value: Boolean) : FactValue
    public data class Number(val value: Long) : FactValue
    public data class TextList(val values: List<String>) : FactValue
}

/**
 * An immutable bag of facts about one subject — typically a single installed
 * app, but the same shape describes a device-wide check.
 *
 * Keys are dotted paths such as `app.accessibility_enabled` or
 * `app.install_source`, matching the identifiers used in rule bundles.
 */
public class Facts private constructor(
    private val values: Map<String, FactValue>,
) {
    public val keys: Set<String> get() = values.keys

    public operator fun get(key: String): FactValue? = values[key]

    public fun has(key: String): Boolean = values.containsKey(key)

    public companion object {
        public fun of(values: Map<String, FactValue>): Facts = Facts(values.toMap())

        public fun builder(): Builder = Builder()
    }

    public class Builder {
        private val values = mutableMapOf<String, FactValue>()

        public fun text(key: String, value: String): Builder = apply {
            values[key] = FactValue.Text(value)
        }

        public fun bool(key: String, value: Boolean): Builder = apply {
            values[key] = FactValue.Bool(value)
        }

        public fun number(key: String, value: Long): Builder = apply {
            values[key] = FactValue.Number(value)
        }

        public fun textList(key: String, value: List<String>): Builder = apply {
            values[key] = FactValue.TextList(value)
        }

        public fun build(): Facts = Facts(values.toMap())
    }
}

/**
 * Well-known fact keys. Centralising them keeps the collector side (Phase 1)
 * and the rule authors honest about spelling. This is not exhaustive — rule
 * bundles may reference new keys as collectors grow — but it documents the
 * device signals the launch rules rely on (FR-DEV-01..05, FR-DEV-09).
 */
public object FactKeys {
    // Identity
    public const val PACKAGE: String = "app.package"
    public const val CERT_SHA256: String = "app.cert_sha256"
    public const val INSTALL_SOURCE: String = "app.install_source"
    public const val INSTALL_TIME: String = "app.install_time"

    // Visibility
    public const val HAS_LAUNCHER_ICON: String = "app.has_launcher_icon"
    public const val STARTS_AT_BOOT: String = "app.starts_at_boot"
    public const val IS_SYSTEM_APP: String = "app.is_system_app"
    public const val IS_UPDATED_SYSTEM_APP: String = "app.is_updated_system_app"

    // Install-source integrity (security review H4)
    public const val INSTALL_SOURCE_MISMATCH: String = "app.install_source_mismatch"
    public const val CERT_CHANGED_ON_UPDATE: String = "app.cert_changed_on_update"

    // The app claims a reserved system/vendor package namespace (android.*,
    // com.android.*, com.google.android.*, …) but is NOT a genuine system-
    // partition app and did not come from a store — i.e. a sideloaded app
    // wearing a system component's name to hide in the app list (market-scan
    // item 5; the classic `com.android.systemservice` disguise).
    public const val POSES_AS_SYSTEM: String = "app.poses_as_system"

    // Derived count of surveillance-grade powers this app holds (FR-DEV-02)
    public const val SURVEILLANCE_POWER_COUNT: String = "app.surveillance_power_count"

    // Dangerous runtime permissions the app has actually been *granted* (not
    // merely requested), collapsed to the surveillance groups a stalkerware
    // product leans on: microphone, camera, sms, call_log, location, contacts.
    // Scoring the granted set — not just the four special-access powers above —
    // is what lets the engine weigh an app that quietly holds the microphone,
    // camera and location at once (market-scan item 3).
    public const val GRANTED_SURVEILLANCE_PERMISSIONS: String = "app.granted_surveillance_permissions"

    // Distinct count of the groups in [GRANTED_SURVEILLANCE_PERMISSIONS].
    public const val GRANTED_SURVEILLANCE_PERMISSION_COUNT: String =
        "app.granted_surveillance_permission_count"

    // Surveillance-grade powers (FR-DEV-02)
    public const val ACCESSIBILITY_ENABLED: String = "app.accessibility_enabled"
    public const val DEVICE_ADMIN: String = "app.device_admin"
    public const val NOTIFICATION_ACCESS: String = "app.notification_access"
    public const val USAGE_ACCESS: String = "app.usage_access"
    public const val DEFAULT_SMS: String = "app.default_sms"
    public const val DEFAULT_DIALER: String = "app.default_dialer"

    // Interception settings (FR-DEV-04)
    public const val USER_CERTIFICATE_ADDED: String = "device.user_certificate_added"
    public const val VPN_ACTIVE: String = "device.vpn_active"
    public const val DEVELOPER_OPTIONS: String = "device.developer_options"
    public const val USB_DEBUGGING: String = "device.usb_debugging"
    public const val WIRELESS_DEBUGGING: String = "device.wireless_debugging"
    public const val THIRD_PARTY_KEYBOARD: String = "app.is_keyboard"
    public const val IS_KNOWN_GOOD_KEYBOARD: String = "app.is_known_good_keyboard"
    public const val WORK_PROFILE_MANAGED: String = "device.work_profile_managed"

    // Observed activity (feeds the "Very likely" vs "Possible" split)
    public const val UPLOADS_SCREEN_OFF: String = "app.uploads_screen_off"
    public const val MIC_WHILE_SCREEN_OFF: String = "app.mic_while_screen_off"

    // Innocent explanations the engine must check before accusing (FR-ALR / risks)
    public const val IS_PARENTAL_CONTROL: String = "app.is_parental_control"
    public const val IS_SCREEN_READER: String = "app.is_screen_reader"
    public const val MANAGED_BY_EMPLOYER: String = "app.managed_by_employer"

    // Known-product match (FR-DEV-01 / FR-ATT-02, FR-DEV-08)
    public const val KNOWN_STALKERWARE_MATCH: String = "app.known_stalkerware_match"
    public const val MERCENARY_INDICATOR_MATCH: String = "app.mercenary_indicator_match"
    public const val PROOF_TEST_FIRED: String = "app.proof_test_fired"

    // The installed APK's own SHA-256 matches a published stalkerware sample
    // hash (Echap samples.csv, market-scan item 4). An exact file match is as
    // definitive as a package/cert match — a renamed sample that was not
    // recompiled still hashes identically.
    public const val KNOWN_STALKERWARE_FILE_MATCH: String = "app.known_stalkerware_file_match"

    // Matches a known *watchware* product — commercial child/employee monitoring
    // that is legal to install on your own device but is routinely repurposed to
    // spy on a partner (Echap watchware.yaml, market-scan item 4). Dual-use, so
    // it is a risk to review, not a confirmed attack.
    public const val WATCHWARE_MATCH: String = "app.watchware_match"
}
