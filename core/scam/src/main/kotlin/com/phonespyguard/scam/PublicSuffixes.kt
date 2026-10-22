package com.phonespyguard.scam

/**
 * A compact public-suffix set — enough to split the registrable domain (eTLD+1)
 * out of a host for the scam checks, without shipping the full Public Suffix
 * List. It covers the single-label TLDs plus the common two-label suffixes
 * (including the country ones a victim is most likely to see, Ghana among them).
 *
 * This is a heuristic aid, not an authority: an unknown suffix falls back to the
 * last two labels, which is safe for the look-alike and brand checks.
 */
public object PublicSuffixes {
    public val COMMON: Set<String> = buildSet {
        // Generic single-label TLDs.
        addAll(
            listOf(
                "com", "net", "org", "info", "biz", "io", "co", "app", "dev",
                "xyz", "top", "site", "online", "shop", "store", "link", "live",
                "me", "tv", "cc", "ru", "cn", "de", "fr", "nl", "uk", "us", "ca",
                "au", "in", "br", "za", "ng", "gh", "ke", "ug", "tz", "zip", "mov",
                "tk", "ml", "ga", "cf", "gq", "pw", "work", "click", "fit",
            ),
        )
        // Common two-label suffixes.
        addAll(
            listOf(
                "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
                "com.gh", "org.gh", "gov.gh", "edu.gh",
                "com.ng", "org.ng", "gov.ng",
                "co.za", "org.za", "gov.za",
                "co.ke", "or.ke", "go.ke",
                "com.au", "net.au", "org.au", "gov.au",
                "co.in", "net.in", "org.in", "gov.in",
                "com.br", "gov.br",
                "co.jp", "or.jp", "ne.jp",
                "com.cn", "gov.cn",
                "com.tr", "com.mx", "com.ar", "com.sg", "com.hk",
            ),
        )
    }
}
