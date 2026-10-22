package com.phonespyguard.detection

/**
 * One indicator of compromise: a package name and/or the SHA-1 of the app's
 * signing certificate (the fingerprint format the public stalkerware datasets
 * publish). At least one of the two is present.
 *
 * Matching semantics differ by list, see [IndicatorSet]:
 *  - For a *known-bad* list (stalkerware, mercenary) an app matches on package
 *    **or** cert. Pinning the cert is what catches a sample that has simply been
 *    renamed to a fresh package but is still signed by the operator's key
 *    (security review C1: "a renamed package evades the list").
 *  - For an *allow-list* (screen readers, parental control, keyboards) an app is
 *    only accepted as benign when the package matches **and** it either presents
 *    the pinned cert or is a genuine system-partition app. The *install source*
 *    is deliberately **not** consulted: `adb install -i com.android.vending`
 *    lets an attacker fake a Play install, so an entry that leaned on the
 *    install source would let a sideloaded impostor borrow the package name
 *    `com.google.android.marvin.talkback` and talk its way out (review N2 / the
 *    round-3 spoofed-source finding). The system-partition flag
 *    (`FLAG_SYSTEM`) cannot be set by a sideload, so it is the one source-free
 *    fallback for a pre-installed component that has no pinned cert yet.
 */
public data class AppIndicator(
    val packageName: String? = null,
    val certSha1: String? = null,
    /** The product name shown to the owner, e.g. "mSpy". */
    val name: String = packageName ?: certSha1 ?: "unknown",
) {
    init {
        require(packageName != null || certSha1 != null) {
            "An indicator must have a package or a cert_sha1"
        }
    }

    /** Known-bad match: package OR cert. A renamed-but-same-key sample still hits. */
    public fun matchesKnownBad(pkg: String, certSha1: String?): Boolean {
        if (packageName != null && pkg.equals(packageName, ignoreCase = true)) return true
        if (this.certSha1 != null && certSha1 != null && certSha1.equals(this.certSha1, ignoreCase = true)) return true
        return false
    }

    /**
     * Allow-list match: the package must match, and the app must be *provably*
     * that app — either it presents the pinned cert, or (for an entry with no
     * cert pinned yet) it is a genuine system-partition app. A claimed install
     * source is never enough, because it can be spoofed with `adb install -i`.
     */
    public fun matchesAllowList(pkg: String, certSha1: String?, isSystemApp: Boolean): Boolean {
        if (packageName == null || !pkg.equals(packageName, ignoreCase = true)) return false
        val pinned = this.certSha1
        return if (pinned != null) {
            certSha1 != null && certSha1.equals(pinned, ignoreCase = true)
        } else {
            isSystemApp
        }
    }
}

/** How the indicator set classified one app. */
public data class AppClassification(
    val knownStalkerware: Boolean,
    val stalkerwareName: String?,
    val mercenaryMatch: Boolean,
    val isScreenReader: Boolean,
    val isParentalControl: Boolean,
    val isKnownGoodKeyboard: Boolean,
)

/**
 * The set of indicators shipped *inside the rule bundle* (security review
 * C1, H2, N2). When a bundle is delivered over the air it is the 2-of-3
 * Ed25519-signed [BundleVerifier] payload, so an attacker cannot add their own
 * package to the "screen reader" allow-list. The copy that ships inside the app
 * is instead protected by the APK's own signature (the app loads the bundled
 * asset without re-checking the detached signature); the thesis states this
 * rather than claiming the in-app copy is separately signature-checked.
 *
 * The collector reads an installed app's package and signing-cert SHA-1 and
 * whether it came from a trusted source, then calls [classify]; the resulting
 * facts (`app.known_stalkerware_match`, `app.is_screen_reader`, …) are what the
 * rules then match. Identity matching lives here, in pure JVM code, so it is
 * unit-tested off-device.
 */
public data class IndicatorSet(
    val stalkerware: List<AppIndicator> = emptyList(),
    val mercenary: List<AppIndicator> = emptyList(),
    val screenReaders: List<AppIndicator> = emptyList(),
    val parentalControl: List<AppIndicator> = emptyList(),
    val knownGoodKeyboards: List<AppIndicator> = emptyList(),
) {
    public val isEmpty: Boolean
        get() = stalkerware.isEmpty() && mercenary.isEmpty() && screenReaders.isEmpty() &&
            parentalControl.isEmpty() && knownGoodKeyboards.isEmpty()

    public val size: Int
        get() = stalkerware.size + mercenary.size + screenReaders.size +
            parentalControl.size + knownGoodKeyboards.size

    /**
     * @param certSha1 the SHA-1 of the app's signing certificate, or null.
     * @param isSystemApp whether the app is a genuine system-partition app
     *   (`FLAG_SYSTEM`/`FLAG_UPDATED_SYSTEM_APP`), which a sideload cannot fake.
     *   An unpinned allow-list entry is honoured only for such an app, never on
     *   a claimed install source (review N2 / round-3 spoofed-source finding).
     */
    public fun classify(pkg: String, certSha1: String?, isSystemApp: Boolean): AppClassification {
        val known = stalkerware.firstOrNull { it.matchesKnownBad(pkg, certSha1) }
        return AppClassification(
            knownStalkerware = known != null,
            stalkerwareName = known?.name,
            mercenaryMatch = mercenary.any { it.matchesKnownBad(pkg, certSha1) },
            isScreenReader = screenReaders.any { it.matchesAllowList(pkg, certSha1, isSystemApp) },
            isParentalControl = parentalControl.any { it.matchesAllowList(pkg, certSha1, isSystemApp) },
            isKnownGoodKeyboard = knownGoodKeyboards.any { it.matchesAllowList(pkg, certSha1, isSystemApp) },
        )
    }
}
