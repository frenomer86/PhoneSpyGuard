package com.phonespyguard.scam

/** One on-device reason a link looks like a scam, with how much it weighs. */
public data class ScamSignal(
    val id: String,
    /** 0..100; higher means more incriminating. */
    val weight: Int,
    /** Plain-language reason the owner can read. */
    val explain: String,
)

/**
 * The on-device link checks (FR-CHK-05). Each check looks only at the parsed
 * link (and the brand directory) — no network, no contacting the link. The
 * checks are deliberately conservative: a single weak signal is a *caution*,
 * not an accusation, and brand impersonation is called only when a real brand is
 * clearly being imitated by someone else's domain.
 */
public class ScamHeuristics(
    private val brands: BrandDirectory = BrandDirectory.bundled(),
) {
    /** All signals a link trips, strongest first. [messageText] gives context for urgency wording. */
    public fun inspect(url: ParsedUrl, messageText: String = ""): List<ScamSignal> {
        val signals = mutableListOf<ScamSignal>()

        if (url.isIpHost) {
            signals += ScamSignal("RAW_IP_HOST", 55, "The link points at a raw IP address, not a named website. Real companies don't send links like this.")
        }
        if (url.isPunycode) {
            signals += ScamSignal("PUNYCODE_HOST", 60, "The web address uses look-alike foreign letters to imitate a real name.")
        }
        if (url.userInfo != null && url.userInfo.contains('.')) {
            signals += ScamSignal("AT_SIGN_SPOOF", 65, "A trusted-looking name sits before an '@', which hides the real site (\"${url.userInfo}\" is not where this goes).")
        }
        if (url.subdomains.size >= 4) {
            signals += ScamSignal("MANY_SUBDOMAINS", 35, "The address is padded with many parts to look longer and more official than it is.")
        }
        if (url.registrableDomain.substringAfterLast('.') in RISKY_TLDS) {
            signals += ScamSignal("RISKY_TLD", 30, "The address ends in \".${url.registrableDomain.substringAfterLast('.')}\", an ending heavily abused for scams.")
        }
        if (url.registrableDomain in SHORTENERS) {
            signals += ScamSignal("URL_SHORTENER", 30, "It's a shortened link, so you can't see where it really leads until you tap it.")
        }
        val hostAndPath = (url.host + url.path).lowercase()
        if (CREDENTIAL_WORDS.any { hostAndPath.contains(it) }) {
            signals += ScamSignal("CREDENTIAL_BAIT", 30, "The link talks about logging in, verifying or securing your account — classic bait to steal your password.")
        }
        if (url.host.count { it == '-' } >= 3) {
            signals += ScamSignal("DASH_STUFFED", 20, "The address is stuffed with dashes to cram a brand name into someone else's site.")
        }

        // Brand impersonation — the strongest on-device signals.
        brandImpersonation(url)?.let { signals += it }

        // Urgency wording in the surrounding message raises the stakes a little.
        val lowerMsg = messageText.lowercase()
        if (URGENCY_WORDS.any { lowerMsg.contains(it) }) {
            signals += ScamSignal("URGENCY_PRESSURE", 15, "The message pressures you to act fast or claims something will be lost — a standard scam tactic.")
        }

        return signals.sortedByDescending { it.weight }
    }

    private fun brandImpersonation(url: ParsedUrl): ScamSignal? {
        // If the registrable domain genuinely belongs to a brand, it's not impersonation.
        if (brands.brandForDomain(url.registrableDomain) != null) return null

        // A brand name used as a subdomain of someone else's domain.
        for (sub in url.subdomains) {
            val brand = brands.brandForAlias(sub)
            if (brand != null) {
                return ScamSignal(
                    "BRAND_IN_SUBDOMAIN", 70,
                    "This looks like ${brand.name}, but the real website is \"${url.registrableDomain}\", which ${brand.name} does not own.",
                )
            }
        }

        // A registrable domain that is a near look-alike of a real brand domain.
        val core = url.registrableDomain.substringBeforeLast('.')
        for (brand in brands.all()) {
            for (domain in brand.domains) {
                val brandCore = domain.substringBeforeLast('.')
                if (core == brandCore) continue
                if (looksLike(core, brandCore)) {
                    return ScamSignal(
                        "LOOKALIKE_DOMAIN", 68,
                        "\"${url.registrableDomain}\" is a near-copy of ${brand.name}'s real address \"$domain\" — one or two letters changed to fool the eye.",
                    )
                }
            }
        }
        return null
    }

    /** A look-alike is an edit distance of 1 on a name of real length, or a digit-for-letter swap. */
    private fun looksLike(a: String, b: String): Boolean {
        if (b.length < 4) return false
        val normalisedA = a.map { HOMOGLYPHS[it] ?: it }.joinToString("")
        if (normalisedA == b) return true
        return editDistanceAtMostOne(a, b)
    }

    private fun editDistanceAtMostOne(a: String, b: String): Boolean {
        if (kotlin.math.abs(a.length - b.length) > 1) return false
        var i = 0; var j = 0; var edits = 0
        while (i < a.length && j < b.length) {
            if (a[i] == b[j]) { i++; j++; continue }
            if (++edits > 1) return false
            when {
                a.length > b.length -> i++
                a.length < b.length -> j++
                else -> { i++; j++ }
            }
        }
        edits += (a.length - i) + (b.length - j)
        return edits <= 1
    }

    public companion object {
        private val RISKY_TLDS = setOf("zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "click", "fit", "work")
        private val SHORTENERS = setOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at")
        private val CREDENTIAL_WORDS = listOf("login", "log-in", "signin", "sign-in", "verify", "secure", "account", "update", "confirm", "webscr", "unlock", "wallet", "password", "otp")
        private val URGENCY_WORDS = listOf("urgent", "immediately", "suspend", "blocked", "within 24", "expire", "verify now", "you have won", "you won", "prize", "refund", "claim now", "account locked", "final notice")
        // Digit/letter swaps commonly used in typosquats.
        private val HOMOGLYPHS = mapOf('1' to 'l', '0' to 'o', '3' to 'e', '5' to 's', '4' to 'a', '7' to 't', '$' to 's')
    }
}
