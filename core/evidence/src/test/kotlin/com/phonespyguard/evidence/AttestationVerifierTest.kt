package com.phonespyguard.evidence

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Fixtures are real X.509 certificates generated with the JDK `keytool`:
 *  - LEAF is an EC key certificate **signed by** ROOT (a self-signed CA),
 *    exactly the shape of an attestation chain's bottom two links.
 *  - OTHER is an unrelated self-signed certificate, used to prove a broken
 *    link and a key-binding mismatch are both rejected.
 */
class AttestationVerifierTest {

    private fun der(b64: String) = Base64.getDecoder().decode(b64)

    private val leaf = der(
        "MIIBazCCARGgAwIBAgIINI2as8IaRPswCgYIKoZIzj0EAwMwGDEWMBQGA1UEAxMNUFNHIFRlc3QgUm9vdDAeFw0yNjEwMjIxNDI3MjJaFw0yNzAxMjAxNDI3MjJaMBsxGTAXBgNVBAMTEFBTRyBFdmlkZW5jZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQklcJ5bb8DfWkfJ6WyxX0wLSA9q/MzhfS+aBwfrJdNmxMWTL76+FtSLePdIcg97EeWjvo8GS9dnu2Zo4ZlR7Iro0IwQDAdBgNVHQ4EFgQUR8hDcgvRnwyF0N/xTgaKvW6suBwwHwYDVR0jBBgwFoAUx6I7+sX859jak3mBqk8mPYqbdScwCgYIKoZIzj0EAwMDSAAwRQIhAI61tCVP2NSvpGJvcBMwf9MCak+zRNpWk+3b9oncwyhhAiAUhlxIN7kf9XA+Z68+kc7q2hCIA0KbZx4ZMhKD1iJ2vQ==",
    )
    private val root = der(
        "MIIBVzCB/6ADAgECAgkAj71X0Ww2UXAwCgYIKoZIzj0EAwMwGDEWMBQGA1UEAxMNUFNHIFRlc3QgUm9vdDAeFw0yNjEwMjIxNDI3MjBaFw0yNzAxMjAxNDI3MjBaMBgxFjAUBgNVBAMTDVBTRyBUZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARFITQFQAwsH89lJPgbt++hxX3/yt9msclZeLqDYuY4onDSTND3bVhtS6zDs0qxARVo/P3oWJNq+15Pp5OLXee8ozIwMDAdBgNVHQ4EFgQUx6I7+sX859jak3mBqk8mPYqbdScwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNHADBEAiBqgVrmQ8fWcU7MUDO4/hJ6QgMXuFUYn67d6QZj2nxOGgIgGArpkMwQObj/HLgsXJR9MojsnPwHqZ+ziYyUS413IGQ=",
    )
    private val other = der(
        "MIIBPjCB5qADAgECAgkAg40RXnDrs3UwCgYIKoZIzj0EAwMwFDESMBAGA1UEAxMJVW5yZWxhdGVkMB4XDTI2MTAyMjE0MjcyM1oXDTI3MDEyMDE0MjcyM1owFDESMBAGA1UEAxMJVW5yZWxhdGVkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM2fhFrcyWvDWZdM5oMR3RjiDUFaCeYCLSe1k7xgCiR3A6+CNZkU3RgR4iAkY7AYhCf3jIaaSCWU7VdEpaeg3+KMhMB8wHQYDVR0OBBYEFEo1NahiVqIrWpauNCDMAg1jgNhsMAoGCCqGSM49BAMDA0cAMEQCICKysbezfQCU03WPL1/Uli9mJTTrg4ssk3iUZ2vjnOiWAiBu2VHyr6S4yUvrliXdHeQfccQzSP8TeCxYpf9MgQnBNQ==",
    )
    private val leafSpki = der(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJJXCeW2/A31pHyelssV9MC0gPavzM4X0vmgcH6yXTZsTFky++vhbUi3j3SHIPexHlo76PBkvXZ7tmaOGZUeyKw==",
    )
    private val otherSpki = der(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM2fhFrcyWvDWZdM5oMR3RjiDUFaCeYCLSe1k7xgCiR3A6+CNZkU3RgR4iAkY7AYhCf3jIaaSCWU7VdEpaeg3+A==",
    )

    @Test
    fun `a linked chain bound to the signing key is a hardware chain`() {
        val r = AttestationVerifier.verifyChain(listOf(leaf, root), leafSpki)
        assertInstanceOf(AttestationVerifier.Result.HardwareChain::class.java, r)
        assertEquals(2, (r as AttestationVerifier.Result.HardwareChain).chainLength)
    }

    @Test
    fun `a chain whose leaf is not the signing key is rejected`() {
        val r = AttestationVerifier.verifyChain(listOf(leaf, root), otherSpki)
        assertInstanceOf(AttestationVerifier.Result.Invalid::class.java, r)
        assertTrue((r as AttestationVerifier.Result.Invalid).reason.contains("signing key"))
    }

    @Test
    fun `a broken link is rejected`() {
        // leaf is signed by root, not by the unrelated 'other' cert.
        val r = AttestationVerifier.verifyChain(listOf(leaf, other), leafSpki)
        assertInstanceOf(AttestationVerifier.Result.Invalid::class.java, r)
        assertTrue((r as AttestationVerifier.Result.Invalid).reason.contains("not signed"))
    }

    @Test
    fun `an empty chain is absent`() {
        assertEquals(AttestationVerifier.Result.Absent, AttestationVerifier.verifyChain(emptyList(), leafSpki))
    }

    @Test
    fun `verifyExport reads the chain and key from an export bundle`() {
        val b64 = Base64.getEncoder()
        val json = """
            {
              "format": "phone-spy-guard.evidence.v1",
              "publicKeySpki": "${b64.encodeToString(leafSpki)}",
              "attestationChain": ["${b64.encodeToString(leaf)}", "${b64.encodeToString(root)}"]
            }
        """.trimIndent()
        val r = AttestationVerifier.verifyExport(json)
        assertInstanceOf(AttestationVerifier.Result.HardwareChain::class.java, r)
    }

    @Test
    fun `verifyExport with no chain is absent`() {
        val json = """{"format":"phone-spy-guard.evidence.v1","publicKeySpki":"${Base64.getEncoder().encodeToString(leafSpki)}"}"""
        assertEquals(AttestationVerifier.Result.Absent, AttestationVerifier.verifyExport(json))
    }
}
