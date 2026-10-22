package com.phonespyguard.scam

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class HashPrefixCheckerTest {
    @Test fun knownBadDomainMatches() {
        val checker = HashPrefixChecker.offline(listOf("bad-site.example", "phish.example"))
        assertTrue(checker.isKnownBad("bad-site.example"))
        assertTrue(checker.isKnownBad("BAD-SITE.EXAMPLE")) // case-insensitive
    }

    @Test fun unknownDomainDoesNotMatch() {
        val checker = HashPrefixChecker.offline(listOf("bad-site.example"))
        assertFalse(checker.isKnownBad("good-site.example"))
    }

    @Test fun safeDomainIsNeverSentToTheSource() {
        // The local prefix gate means a domain whose prefix isn't flagged never
        // reaches the source at all (security review M4).
        var queries = 0
        val localPrefixes = HashPrefixChecker.prefixesOf(listOf("bad-site.example"))
        val source = ReputationSource { prefix ->
            queries++
            setOf(HashPrefixChecker.sha256Hex("bad-site.example")).filter { it.startsWith(prefix) }.toSet()
        }
        val checker = HashPrefixChecker(source, localPrefixes)
        assertFalse(checker.isKnownBad("totally-unrelated-domain-xyz.example"))
        assertEquals(0, queries, "a safe domain must not be queried")
    }

    @Test fun onlyPrefixIsSentOnALocalHit() {
        var seenQuery: String? = null
        val localPrefixes = HashPrefixChecker.prefixesOf(listOf("bad-site.example"), prefixLength = 4)
        val source = ReputationSource { prefix ->
            seenQuery = prefix
            setOf(HashPrefixChecker.sha256Hex("bad-site.example")).filter { it.startsWith(prefix) }.toSet()
        }
        val checker = HashPrefixChecker(source, localPrefixes, prefixLength = 4)
        assertTrue(checker.isKnownBad("bad-site.example"))
        assertNotNull(seenQuery)
        assertEquals(4, seenQuery!!.length)
        assertTrue(HashPrefixChecker.sha256Hex("bad-site.example").startsWith(seenQuery!!))
    }

    @Test fun hashIsStableSha256() {
        // Known SHA-256 of the ASCII string "abc".
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            HashPrefixChecker.sha256Hex("abc"),
        )
    }
}
