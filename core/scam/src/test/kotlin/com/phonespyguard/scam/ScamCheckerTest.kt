package com.phonespyguard.scam

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ScamCheckerTest {
    private val checker = ScamChecker()

    @Test fun genuineBrandDomainIsSafe() {
        val v = checker.check("Your receipt is at https://www.paypal.com/activity")
        assertEquals(ScamLevel.LIKELY_SAFE, v.level)
    }

    @Test fun brandInSubdomainIsLikelyScam() {
        val v = checker.check("Confirm your account: http://paypal.secure-login.ru/verify")
        assertEquals(ScamLevel.LIKELY_SCAM, v.level)
        assertTrue(v.findings[0].signals.any { it.id == "BRAND_IN_SUBDOMAIN" })
        assertTrue(v.nextStep.contains("PayPal"))
    }

    @Test fun lookalikeDomainIsLikelyScam() {
        val v = checker.check("Login needed: https://paypa1.com/signin")
        assertEquals(ScamLevel.LIKELY_SCAM, v.level)
        assertTrue(v.findings[0].signals.any { it.id == "LOOKALIKE_DOMAIN" })
    }

    @Test fun atSignSpoofIsLikelyScam() {
        val v = checker.check("Update here http://apple.com@198.51.100.7/id")
        assertEquals(ScamLevel.LIKELY_SCAM, v.level)
    }

    @Test fun momoImpersonationCaught() {
        val v = checker.check("MTN: your MoMo wallet is blocked, verify at mtn.momo-unlock.top/verify within 24 hours")
        assertEquals(ScamLevel.LIKELY_SCAM, v.level)
        assertTrue(v.reasons.isNotEmpty())
    }

    @Test fun mildSignalsAreCaution() {
        // Short link, no brand imitation: a caution, not an accusation.
        val v = checker.check("here you go: https://bit.ly/3xYz")
        assertEquals(ScamLevel.CAUTION, v.level)
    }

    @Test fun noLinkGivesNoLink() {
        val v = checker.check("Hey, are we still on for lunch?")
        assertEquals(ScamLevel.NO_LINK, v.level)
        assertFalse(v.hasLink)
    }

    @Test fun momoReversalWithNoLinkIsFlagged() {
        val v = checker.check("Hello, I sent GHS 500 to your number by mistake, please kindly reverse the transaction to me.")
        assertEquals(ScamLevel.CAUTION, v.level)
        assertTrue(v.messageSignals.any { it.id == "MONEY_REVERSAL" })
        assertFalse(v.hasLink)
    }

    @Test fun otpRequestWithNoLinkIsLikelyScam() {
        val v = checker.check("This is MTN customer care. Please send the one-time code we just texted you to confirm your wallet.")
        assertEquals(ScamLevel.LIKELY_SCAM, v.level)
        assertTrue(v.messageSignals.any { it.id == "CODE_REQUEST" })
    }

    @Test fun legitimateOtpDeliveryIsNotFlagged() {
        // The most common security SMS people get must not be called a scam (review N5).
        for (sms in listOf(
            "Your verification code is 482913. Do not share it with anyone.",
            "G-558213 is your Google verification code.",
            "123456 is your OTP. Never share this code. - MTN MoMo",
            "Use this code 904521 to log in. We will never ask you for it.",
        )) {
            val v = checker.check(sms)
            assertTrue(v.messageSignals.none { it.id == "CODE_REQUEST" }, "false positive on: $sms")
            assertFalse(v.level == ScamLevel.LIKELY_SCAM, "wrongly LIKELY_SCAM: $sms")
        }
    }

    @Test fun scamAskingYouToSendYourCodeIsFlagged() {
        val v = checker.check("MoMo security: please send me the one-time code we just sent you to verify your wallet.")
        assertTrue(v.messageSignals.any { it.id == "CODE_REQUEST" })
    }

    @Test fun messageTextCanRaiseALinkVerdict() {
        // A bare shortener is only CAUTION, but a prize + account threat around it pushes higher.
        val v = checker.check("Congratulations you won a cash prize! Your account will be blocked unless you claim at https://bit.ly/abc")
        assertEquals(ScamLevel.LIKELY_SCAM, v.level)
        assertTrue(v.messageSignals.isNotEmpty())
    }

    @Test fun knownBadBeatsEverything() {
        val rep = HashPrefixChecker.offline(listOf("totally-fine.com"))
        val c = ScamChecker(reputation = rep)
        val v = c.check("see https://www.totally-fine.com/")
        assertEquals(ScamLevel.KNOWN_SCAM, v.level)
        assertTrue(v.nextStep.contains("known scam", ignoreCase = true))
    }

    @Test fun worstLinkDecidesOverall() {
        val v = checker.check("Two links: https://www.apple.com/ and http://apple.secure-id.ru/verify")
        assertEquals(ScamLevel.LIKELY_SCAM, v.level)
        assertEquals(2, v.findings.size)
    }

    @Test fun rawIpAndCredentialBaitAccumulate() {
        val v = checker.check("http://203.0.113.9/account/login/verify")
        // raw IP (55) + credential bait (30) => >= 70 => likely scam
        assertEquals(ScamLevel.LIKELY_SCAM, v.level)
    }
}
