package com.phonespyguard.scam

import java.security.MessageDigest
import java.util.Locale

/**
 * Checks a link's domain against a reputation list the way Safe Browsing does,
 * so that **most lookups never leave the device at all** (FR-CHK-05,
 * NFR-SEC-12, security review M4).
 *
 * A set of short hash *prefixes* of known-bad domains ships on the device. A
 * domain is hashed (SHA-256) and its prefix checked against that local set:
 *  - on a local miss (the overwhelming majority of links) the answer is "not
 *    known bad" and nothing is sent anywhere;
 *  - only on a local hit does the checker ask the [ReputationSource] for the
 *    full hashes sharing that prefix, and finish the match locally.
 *
 * So the server is contacted only for a domain whose prefix already collides
 * with a known-bad one, and even then it is told a prefix, not the domain. This
 * is a weaker privacy claim than "one of thousands" — a short prefix does not
 * hide a popular domain well — which is exactly why the local prefix gate
 * matters: a safe link is never disclosed at all.
 *
 * [StaticReputationSource] provides a fully offline list for tests and for when
 * the device has no connection; its prefixes seed the local gate.
 */
public class HashPrefixChecker(
    private val source: ReputationSource,
    /** Known-bad hash prefixes held on the device; only a prefix in here is queried. */
    private val localPrefixes: Set<String>,
    /** Hex characters compared as the prefix. Shorter = larger buckets = less disclosed. */
    private val prefixLength: Int = 4,
) {
    /**
     * True when the domain's full hash is on the reputation list. Returns false
     * without any network call when the domain's prefix is not locally flagged.
     */
    public fun isKnownBad(registrableDomain: String): Boolean {
        val full = sha256Hex(registrableDomain.lowercase(Locale.ROOT))
        val prefix = full.take(prefixLength)
        if (prefix !in localPrefixes) return false
        val candidates = source.lookup(prefix)
        return candidates.any { it.equals(full, ignoreCase = true) }
    }

    public companion object {
        public fun sha256Hex(value: String): String =
            MessageDigest.getInstance("SHA-256")
                .digest(value.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }

        /** The prefix set a device would hold for a given known-bad list. */
        public fun prefixesOf(knownBadDomains: Collection<String>, prefixLength: Int = 4): Set<String> =
            knownBadDomains
                .map { sha256Hex(it.lowercase(Locale.ROOT)).take(prefixLength) }
                .toSet()

        /** Build a checker and its local prefix gate from one offline list (tests / offline use). */
        public fun offline(knownBadDomains: Collection<String>, prefixLength: Int = 4): HashPrefixChecker =
            HashPrefixChecker(
                source = StaticReputationSource(knownBadDomains),
                localPrefixes = prefixesOf(knownBadDomains, prefixLength),
                prefixLength = prefixLength,
            )
    }
}

/**
 * Answers a prefix query with the full known-bad hashes that share the prefix.
 * On-device this is backed by the signed reputation feed; it is the only part of
 * the scam check that may touch the network, and it is asked only on a local
 * prefix hit, and even then is told a prefix, never the domain.
 */
public fun interface ReputationSource {
    public fun lookup(hashPrefix: String): Set<String>
}

/**
 * A fully offline reputation source built from a set of known-bad domains. The
 * app ships a small signed starter list so a scan still flags the worst-known
 * domains with no connection; the online source extends it.
 */
public class StaticReputationSource(knownBadDomains: Collection<String>) : ReputationSource {
    private val hashes: Set<String> =
        knownBadDomains.map { HashPrefixChecker.sha256Hex(it.lowercase(Locale.ROOT)) }.toSet()

    override fun lookup(hashPrefix: String): Set<String> =
        hashes.filter { it.startsWith(hashPrefix) }.toSet()
}
