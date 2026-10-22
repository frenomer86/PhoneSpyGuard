package com.phonespyguard.safety

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SafetyPlaybookTest {
    private val playbook = SafetyPlaybook.bundled()
    private val advisor = SafetyAdvisor(playbook)

    @Test fun bundledLoads() {
        assertTrue(playbook.cardCount >= 10)
        assertTrue(playbook.supportCount >= 5)
    }

    @Test fun cardsForSituationAppendGeneralAndSortByPriority() {
        val cards = playbook.cardsFor(SafetySituation.SUSPECT_MONITORED)
        // Includes the suspect cards plus the GENERAL ones.
        assertTrue(cards.any { it.situation == SafetySituation.SUSPECT_MONITORED })
        assertTrue(cards.any { it.situation == SafetySituation.GENERAL })
        val priorities = cards.map { it.priority }
        assertEquals(priorities.sorted(), priorities)
    }

    @Test fun generalSituationDoesNotDuplicateGeneral() {
        val cards = playbook.cardsFor(SafetySituation.GENERAL)
        assertTrue(cards.all { it.situation == SafetySituation.GENERAL })
        assertEquals(cards.size, cards.distinctBy { it.id }.size)
    }

    @Test fun confirmedOutcomeLeadsWithEmergencyThenTipOffWarning() {
        val cards = advisor.forDeviceOutcome(DetectionOutcome.CONFIRMED)
        assertFalse(cards.isEmpty())
        // The emergency card always comes first.
        assertEquals("GEN-EMERGENCY", cards.first().id)
        // The first situation-specific card must be the "removal can tip them off" warning.
        val firstSpecific = cards.first { it.situation != SafetySituation.GENERAL }
        assertEquals("BEF-NO-TIP-OFF", firstSpecific.id)
        // And it must include saving evidence before clean-up.
        assertTrue(cards.any { it.id == "BEF-EVIDENCE-FIRST" })
    }

    @Test fun veryLikelyAlsoLeadsWithTipOffWarning() {
        val cards = advisor.forDeviceOutcome(DetectionOutcome.VERY_LIKELY)
        val firstSpecific = cards.first { it.situation != SafetySituation.GENERAL }
        assertEquals("BEF-NO-TIP-OFF", firstSpecific.id)
    }

    @Test fun possibleOutcomeLeadsWithSuspectGuidance() {
        val cards = advisor.forDeviceOutcome(DetectionOutcome.POSSIBLE)
        assertTrue(cards.any { it.situation == SafetySituation.SUSPECT_MONITORED })
        assertFalse(cards.any { it.id == "BEF-NO-TIP-OFF" })
    }

    @Test fun cleanOutcomeShowsGeneralOnly() {
        val cards = advisor.forDeviceOutcome(DetectionOutcome.NONE)
        assertTrue(cards.isNotEmpty())
        assertTrue(cards.all { it.situation == SafetySituation.GENERAL })
    }

    @Test fun advisorCardsHaveNoDuplicates() {
        val cards = advisor.forDeviceOutcome(DetectionOutcome.CONFIRMED)
        assertEquals(cards.size, cards.distinctBy { it.id }.size)
    }

    @Test fun supportForCountryIncludesInternational() {
        val gh = playbook.supportFor("GH")
        assertTrue(gh.any { it.country == "GH" })
        assertTrue(gh.any { it.country == "INTL" }, "international resources should always be offered")
        // Ghana helplines, kept in step with the iPhone companion.
        assertTrue(gh.any { it.contact == "292" }, "Ghana CSA line")
        assertTrue(gh.any { it.contact == "0800 111 222" }, "Ghana GBV support line")
        assertTrue(gh.any { it.contact == "191" }, "Ghana Police emergency line")
    }

    @Test fun supportForUnknownCountryStillGivesInternational() {
        val xx = playbook.supportFor("XX")
        assertTrue(xx.isNotEmpty())
        assertTrue(xx.all { it.country == "INTL" })
    }

    @Test fun emergencyCardIsHighestPriority() {
        val general = playbook.cardsFor(SafetySituation.GENERAL)
        assertEquals("GEN-EMERGENCY", general.first().id)
    }
}
