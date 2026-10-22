package com.phonespyguard.accounts

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class AccountAuditTest {
    private val audit = AccountAudit.bundled()

    @Test fun bundledLoadsAndHasUniqueIds() {
        assertTrue(audit.size >= 15)
        assertEquals(audit.size, audit.steps.map { it.id }.toSet().size)
    }

    @Test fun coversTheRequiredCategories() {
        val categories = audit.steps.map { it.category }.toSet()
        // FR-ACC calls out sessions, 2FA, recovery, forwarding, location and connected apps.
        listOf(
            AuditCategory.LINKED_SESSIONS,
            AuditCategory.TWO_FACTOR,
            AuditCategory.RECOVERY,
            AuditCategory.EMAIL_FORWARDING,
            AuditCategory.LOCATION_SHARING,
            AuditCategory.CONNECTED_APPS,
        ).forEach { assertTrue(it in categories, "missing category $it") }
    }

    @Test fun filtersByService() {
        val whatsapp = audit.forService(AccountService.WHATSAPP)
        assertTrue(whatsapp.isNotEmpty())
        assertTrue(whatsapp.all { it.service == AccountService.WHATSAPP })
    }

    @Test fun highSeverityProblemIsActNow() {
        val report = audit.report(mapOf("WA-SESSIONS" to AuditAnswer.FOUND_PROBLEM))
        assertEquals(AuditRisk.ACT_NOW, report.risk)
        assertEquals(1, report.problems.size)
        assertTrue(report.nextActions.first().contains("Log out"))
    }

    @Test fun mediumOnlyProblemIsAttention() {
        // Answer every step, with one medium-severity problem and the rest normal.
        val answers = audit.steps.associate { step ->
            step.id to if (step.id == "IG-SESSIONS") AuditAnswer.FOUND_PROBLEM else AuditAnswer.LOOKS_NORMAL
        }
        val report = audit.report(answers)
        assertEquals(AuditRisk.ATTENTION, report.risk)
    }

    @Test fun cantFindCountsAsUnresolvedNotSafe() {
        val answers = audit.steps.associate { it.id to AuditAnswer.LOOKS_NORMAL }
            .toMutableMap().apply { this["GOOGLE-RECOVERY"] = AuditAnswer.CANT_FIND }
        val report = audit.report(answers)
        assertEquals(1, report.unresolved.size)
        // Every step was answered and no problem was found, but one answer is
        // CANT_FIND. A "can't find it" is never safe, so the audit must read
        // INCOMPLETE, not CLEAR (bug found by the desktop thread; matches desktop).
        assertEquals(AuditRisk.INCOMPLETE, report.risk)
        assertTrue(report.unresolved.first().id == "GOOGLE-RECOVERY")
    }

    @Test fun incompleteWhenNotEverythingChecked() {
        val report = audit.report(mapOf("WA-2FA" to AuditAnswer.LOOKS_NORMAL))
        assertEquals(AuditRisk.INCOMPLETE, report.risk)
        assertEquals(1, report.checkedSteps)
    }

    @Test fun allNormalIsClear() {
        val answers = audit.steps.associate { it.id to AuditAnswer.LOOKS_NORMAL }
        val report = audit.report(answers)
        assertEquals(AuditRisk.CLEAR, report.risk)
        assertTrue(report.problems.isEmpty())
    }

    @Test fun nextActionsSortHighSeverityFirst() {
        val report = audit.report(
            mapOf(
                "IG-SESSIONS" to AuditAnswer.FOUND_PROBLEM, // medium
                "WA-SESSIONS" to AuditAnswer.FOUND_PROBLEM, // high
            ),
        )
        assertEquals(AuditRisk.ACT_NOW, report.risk)
        assertEquals(AuditSeverity.HIGH, report.problems.sortedBy { it.severity.ordinal }.first().severity)
        assertTrue(report.nextActions.first().startsWith("Linked devices on WhatsApp"))
    }

    @Test fun duplicateIdRejected() {
        val bad = """{"steps":[
            {"id":"X","service":"GOOGLE","category":"TWO_FACTOR","severity":"LOW","title":"a","where":"w","expected":"e","dangerSign":"d","fix":"f"},
            {"id":"X","service":"GOOGLE","category":"TWO_FACTOR","severity":"LOW","title":"b","where":"w","expected":"e","dangerSign":"d","fix":"f"}
        ]}"""
        assertThrows<IllegalArgumentException> { AccountAudit.fromJson(bad) }
    }
}
