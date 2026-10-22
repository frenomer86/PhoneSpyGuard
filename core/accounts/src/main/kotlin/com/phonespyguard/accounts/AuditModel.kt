package com.phonespyguard.accounts

import kotlinx.serialization.Serializable

/**
 * The account a step is about. The app can't read these accounts — by design it
 * holds none of those powers — so the audit is *guided*: it walks the owner
 * through checking each account themselves and records what they find (FR-ACC).
 */
@Serializable
public enum class AccountService {
    WHATSAPP, TELEGRAM, SIGNAL, FACEBOOK, INSTAGRAM, GOOGLE, APPLE, MICROSOFT, EMAIL,
}

/** The kind of exposure a step looks for. */
@Serializable
public enum class AuditCategory {
    /** Other phones/computers or browsers currently logged into the account. */
    LINKED_SESSIONS,

    /** Whether a second factor is on, so a stolen password isn't enough. */
    TWO_FACTOR,

    /** Recovery email / phone an attacker could have swapped to themselves. */
    RECOVERY,

    /** Mail silently forwarded or filtered away to hide alerts. */
    EMAIL_FORWARDING,

    /** Location shared with a person or an app. */
    LOCATION_SHARING,

    /** Third-party apps with standing access to the account. */
    CONNECTED_APPS,

    /** Alerts for new sign-ins, so a future intrusion is noticed. */
    LOGIN_ALERTS,
}

/** How serious an unexpected finding on this step is. */
@Serializable
public enum class AuditSeverity { HIGH, MEDIUM, LOW }

/**
 * One guided step: where to look in the real app, what a normal result is, the
 * danger sign that means someone else may be in, and how to fix it. The wording
 * is deliberately plain and action-first.
 */
@Serializable
public data class AuditStep(
    val id: String,
    val service: AccountService,
    val category: AuditCategory,
    val severity: AuditSeverity,
    /** What this step is, in a few words. */
    val title: String,
    /** How to reach the setting in the real app. */
    val where: String,
    /** What a normal, safe result looks like. */
    val expected: String,
    /** The sign that something is wrong. */
    val dangerSign: String,
    /** What to do if the danger sign is present. */
    val fix: String,
)

/** What the owner reported for a step after looking. */
@Serializable
public enum class AuditAnswer {
    NOT_CHECKED,

    /** Looked, everything matched the expected safe result. */
    LOOKS_NORMAL,

    /** Looked, saw the danger sign. */
    FOUND_PROBLEM,

    /** Couldn't find the setting (treated as still-open, not safe). */
    CANT_FIND,
}
