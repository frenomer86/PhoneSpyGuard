package com.phonespyguard.scam

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class UrlExtractorTest {
    private val extractor = UrlExtractor()

    @Test fun findsPlainUrl() {
        val urls = extractor.extract("Please visit https://login.paypal.com/secure now")
        assertEquals(1, urls.size)
        val u = urls[0]
        assertEquals("paypal.com", u.registrableDomain)
        assertEquals(listOf("login"), u.subdomains)
        assertEquals("/secure", u.path)
    }

    @Test fun findsBareDomainWithoutScheme() {
        val urls = extractor.extract("go to paypal-secure.com/login")
        assertEquals(1, urls.size)
        assertEquals("paypal-secure.com", urls[0].registrableDomain)
        assertEquals("http", urls[0].scheme)
    }

    @Test fun deobfuscatesBracketDotAndHxxp() {
        val urls = extractor.extract("tap hxxps://paypal[.]com[.]secure[.]ru to fix")
        assertEquals(1, urls.size)
        assertEquals("secure.ru", urls[0].registrableDomain)
    }

    @Test fun handlesDotSpelledOut() {
        val urls = extractor.extract("open evil dot example dot com please")
        assertEquals(1, urls.size)
        assertEquals("example.com", urls[0].registrableDomain)
    }

    @Test fun detectsIpHost() {
        val urls = extractor.extract("http://203.0.113.9/login")
        assertEquals(1, urls.size)
        assertTrue(urls[0].isIpHost)
        assertEquals("203.0.113.9", urls[0].registrableDomain)
    }

    @Test fun detectsAtSignUserInfo() {
        val urls = extractor.extract("http://paypal.com@evil.ru/go")
        assertEquals(1, urls.size)
        assertEquals("evil.ru", urls[0].registrableDomain)
        assertEquals("paypal.com", urls[0].userInfo)
    }

    @Test fun multiLevelSuffixGivesCorrectRegistrable() {
        val urls = extractor.extract("see secure.mtn.com.gh/wallet")
        assertEquals(1, urls.size)
        assertEquals("mtn.com.gh", urls[0].registrableDomain)
        assertEquals(listOf("secure"), urls[0].subdomains)
    }

    @Test fun punycodeFlagged() {
        val urls = extractor.extract("https://xn--pypal-4ve.com/login")
        assertEquals(1, urls.size)
        assertTrue(urls[0].isPunycode)
    }

    @Test fun plainWordsAreNotLinks() {
        assertTrue(extractor.extract("call me tomorrow about the thing").isEmpty())
    }

    @Test fun stripsTrailingPunctuation() {
        val urls = extractor.extract("is this real: paypal-secure.com.")
        assertEquals("paypal-secure.com", urls[0].registrableDomain)
    }

    @Test fun deduplicatesRepeatedLink() {
        val urls = extractor.extract("paypal.com paypal.com paypal.com")
        assertEquals(1, urls.size)
    }
}
