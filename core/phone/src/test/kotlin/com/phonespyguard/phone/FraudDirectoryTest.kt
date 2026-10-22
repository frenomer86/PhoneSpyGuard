package com.phonespyguard.phone

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FraudDirectoryTest {

    private val directory = FraudDirectory.bundled()

    @Test
    fun `bundled directory loads countries`() {
        assertTrue(directory.countryCount >= 2)
        assertTrue(directory.hasCountry("GB"))
    }

    @Test
    fun `ghana is covered with a verified report line (M5)`() {
        // The Ghana entry carries only lines we can verify (the Cyber Security
        // Authority 292 short code). Unverified mobile-money "customer care"
        // numbers were removed rather than ship a wrong number a victim might
        // call — a stale fraud line is worse than none.
        assertTrue(directory.hasCountry("GH"))
        val gh = directory.forCountry("GH")
        assertTrue(gh.isNotEmpty())
        assertTrue(gh.any { it.kind == FraudContact.Kind.OPERATOR_FRAUD_LINE })
    }

    @Test
    fun `lookup is case-insensitive`() {
        assertEquals(directory.forCountry("GB"), directory.forCountry("gb"))
        assertTrue(directory.forCountry("gb").isNotEmpty())
    }

    @Test
    fun `an uncovered country returns an empty list, not an error`() {
        assertFalse(directory.hasCountry("ZZ"))
        assertTrue(directory.forCountry("ZZ").isEmpty())
    }

    @Test
    fun `parses contacts with their kind`() {
        val gb = directory.forCountry("GB")
        assertTrue(gb.any { it.kind == FraudContact.Kind.BANK_SUPPORT })
    }

    @Test
    fun `parses from an inline document`() {
        val json = """
            {"countries":[{"country":"gh","contacts":[
              {"name":"Op","number":"100","kind":"MOBILE_MONEY"}
            ]}]}
        """.trimIndent()
        val d = FraudDirectory.fromJson(json)
        assertEquals(FraudContact.Kind.MOBILE_MONEY, d.forCountry("GH").single().kind)
    }
}
