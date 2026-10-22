package com.phonespyguard.accounts

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
private data class AuditFile(val steps: List<AuditStep>)

/**
 * The guided account-security audit (FR-ACC). It holds the ordered list of steps
 * the owner works through, grouped by the account and the kind of exposure, and
 * turns the owner's answers into a plain [AuditReport].
 *
 * The app never reads the accounts itself; every step is something the owner
 * checks in the real app and reports back. That keeps the app free of any
 * account access an attacker could later abuse.
 */
public class AccountAudit private constructor(
    public val steps: List<AuditStep>,
) {
    public val size: Int get() = steps.size

    public fun forService(service: AccountService): List<AuditStep> =
        steps.filter { it.service == service }

    public fun servicesCovered(): List<AccountService> =
        steps.map { it.service }.distinct()

    public fun step(id: String): AuditStep? = steps.firstOrNull { it.id == id }

    /**
     * Summarise the owner's answers. A step the owner couldn't find counts as
     * still open (an attacker hides exactly these), never as safe.
     */
    public fun report(answers: Map<String, AuditAnswer>): AuditReport {
        val problems = mutableListOf<AuditStep>()
        val unresolved = mutableListOf<AuditStep>()
        var checked = 0
        for (step in steps) {
            when (answers[step.id] ?: AuditAnswer.NOT_CHECKED) {
                AuditAnswer.FOUND_PROBLEM -> { problems += step; checked++ }
                AuditAnswer.CANT_FIND -> { unresolved += step; checked++ }
                AuditAnswer.LOOKS_NORMAL -> checked++
                AuditAnswer.NOT_CHECKED -> Unit
            }
        }
        val level = when {
            problems.any { it.severity == AuditSeverity.HIGH } -> AuditRisk.ACT_NOW
            problems.isNotEmpty() -> AuditRisk.ATTENTION
            // Not everything was answered, OR a step was answered CANT_FIND. A
            // "can't find it" is never safe (the setting may be hidden by the
            // person watching), so it keeps the whole audit INCOMPLETE rather
            // than letting it read CLEAR (bug found by the desktop thread;
            // matches the desktop engine).
            checked < steps.size || unresolved.isNotEmpty() -> AuditRisk.INCOMPLETE
            else -> AuditRisk.CLEAR
        }
        // Fixes, highest severity first, for the problems actually found.
        val nextActions = problems
            .sortedBy { it.severity.ordinal }
            .map { "${it.title}: ${it.fix}" }
        return AuditReport(
            risk = level,
            totalSteps = steps.size,
            checkedSteps = checked,
            problems = problems,
            unresolved = unresolved,
            nextActions = nextActions,
        )
    }

    public companion object {
        public fun fromJson(text: String): AccountAudit {
            val parsed = Json { ignoreUnknownKeys = true }.decodeFromString<AuditFile>(text)
            require(parsed.steps.map { it.id }.toSet().size == parsed.steps.size) {
                "duplicate audit step id"
            }
            return AccountAudit(parsed.steps)
        }

        public fun bundled(): AccountAudit {
            val text = AccountAudit::class.java
                .getResourceAsStream("/accounts/account-audit.json")
                ?.readBytes()?.toString(Charsets.UTF_8)
                ?: error("bundled account audit missing")
            return fromJson(text)
        }
    }
}

/** The overall standing after the owner's answers. */
public enum class AuditRisk {
    /** A high-severity problem was found — do the fix now. */
    ACT_NOW,

    /** A problem was found that needs attention. */
    ATTENTION,

    /** No problem found, but something was left unchecked or couldn't be confirmed (a CANT_FIND). */
    INCOMPLETE,

    /** Every step was checked and confirmed normal — nothing stood out. */
    CLEAR,
}

/** The owner-facing result of a run through the audit. */
public data class AuditReport(
    val risk: AuditRisk,
    val totalSteps: Int,
    val checkedSteps: Int,
    val problems: List<AuditStep>,
    val unresolved: List<AuditStep>,
    val nextActions: List<String>,
)
