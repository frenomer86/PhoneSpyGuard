package com.phonespyguard.safety

import kotlinx.serialization.Serializable

/**
 * The situation the owner is in, which decides what safety guidance comes first
 * (FR-SAF, FR-ALR). The ordering matters: this app is used by people who may be
 * living with the person spying on them, so "stay safe" always comes before
 * "clean the phone".
 */
@Serializable
public enum class SafetySituation {
    /** Shown before the owner removes anything — removal can tip off a watcher. */
    BEFORE_REMOVING,

    /** The owner suspects they're being monitored but nothing is confirmed. */
    SUSPECT_MONITORED,

    /** A detection is confirmed or very likely. */
    CONFIRMED_SPYWARE,

    /** A phone-number / SIM-swap / forwarding fraud alert. */
    PHONE_FRAUD,

    /** General standing advice, always available. */
    GENERAL,
}

/** One piece of safety guidance, written plainly and action-first. */
@Serializable
public data class SafetyCard(
    val id: String,
    val situation: SafetySituation,
    /** Lower shows first. */
    val priority: Int,
    val title: String,
    val body: String,
)

/** The kind of help a support resource offers. */
@Serializable
public enum class SupportKind {
    EMERGENCY,
    DOMESTIC_ABUSE_HOTLINE,
    STALKING_SUPPORT,
    LEGAL_AID,
    CYBERCRIME_REPORT,
}

/** A verified place to get help. Kept separate from the fraud-line directory. */
@Serializable
public data class SupportResource(
    val name: String,
    /** A phone number, short code, or URL. */
    val contact: String,
    val kind: SupportKind,
    /** ISO 3166-1 alpha-2, or "INTL" for an international resource. */
    val country: String,
    val note: String = "",
)
