package com.phonespyguard.phone

/**
 * The GSM supplementary-service ("MMI") codes behind the phone-number guard
 * (FR-PHN-02). Call forwarding is what fraudsters abuse: after a scam call they
 * get the victim to dial a conditional-forwarding code so that bank and
 * WhatsApp one-time codes ring to the attacker instead. The app offers the
 * owner one-tap *status checks* and *cancel codes*, each explained in plain
 * words, so they can see and undo forwarding without memorising star codes.
 *
 * These builders produce the standard codes only; dialling them is the Android
 * layer's job (and the app never sets forwarding on, only checks and cancels).
 */

/** A forwarding condition, with its GSM service code (SC). */
public enum class ForwardingType(public val serviceCode: String, public val label: String) {
    UNCONDITIONAL("21", "always"),
    BUSY("67", "when your line is busy"),
    NO_REPLY("61", "when you don't answer"),
    NOT_REACHABLE("62", "when your phone is unreachable"),
    ALL("002", "all call forwarding"),
    ALL_CONDITIONAL("004", "all conditional forwarding (busy, no-reply, unreachable)"),
}

/** What the owner wants to do with a forwarding rule. */
public enum class MmiAction { INTERROGATE, DEACTIVATE, ERASE, REGISTER }

/** A dialable MMI string with a plain-language explanation of what it does. */
public data class UssdCode(val code: String, val explanation: String)

public object ForwardingCodes {

    /**
     * Build the MMI code for [type] + [action]. REGISTER requires a [number]
     * and only applies to a specific condition, never to the "all" aggregates.
     */
    public fun build(type: ForwardingType, action: MmiAction, number: String? = null): UssdCode {
        val sc = type.serviceCode
        return when (action) {
            MmiAction.INTERROGATE -> UssdCode(
                "*#$sc#",
                "Checks whether calls are being forwarded ${type.label}. Nothing is changed.",
            )
            MmiAction.DEACTIVATE -> UssdCode(
                "#$sc#",
                "Turns off call forwarding ${type.label}, but keeps the forwarding number stored.",
            )
            MmiAction.ERASE -> UssdCode(
                "##$sc#",
                "Cancels call forwarding ${type.label} and erases the stored number.",
            )
            MmiAction.REGISTER -> {
                require(type != ForwardingType.ALL && type != ForwardingType.ALL_CONDITIONAL) {
                    "Cannot register a number for ${type.name}; it only supports check/cancel"
                }
                val dn = requireNotNull(number) { "REGISTER needs a forwarding number" }
                UssdCode(
                    "**$sc*$dn#",
                    "Forwards calls to $dn ${type.label}. The app never dials this itself.",
                )
            }
        }
    }

    /** The one-tap "cancel everything" code the app surfaces most prominently. */
    public fun cancelAll(): UssdCode = build(ForwardingType.ALL, MmiAction.ERASE)

    /** The one-tap "is anything being forwarded?" check. */
    public fun checkAll(): UssdCode = build(ForwardingType.ALL, MmiAction.INTERROGATE)

    /** Cancel codes for each conditional type — the codes a scam talks victims
     *  into setting, offered here in reverse so they can be undone. */
    public fun conditionalCancels(): List<UssdCode> =
        listOf(ForwardingType.BUSY, ForwardingType.NO_REPLY, ForwardingType.NOT_REACHABLE)
            .map { build(it, MmiAction.ERASE) }
}
