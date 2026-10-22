package com.phonespyguard.scam

/** How dangerous a link is, from the app's point of view. */
public enum class ScamLevel {
    /** On a signed reputation list of known-bad domains — do not open. */
    KNOWN_SCAM,

    /** Impersonates a real brand, or trips several strong signals. */
    LIKELY_SCAM,

    /** Some warning signs, but not conclusive — treat carefully. */
    CAUTION,

    /** A recognised, genuine brand domain, or nothing suspicious found. */
    LIKELY_SAFE,

    /** No link found, so nothing to judge. */
    NO_LINK,
}

/** The checker's finding for one link. */
public data class LinkFinding(
    val url: ParsedUrl,
    val level: ScamLevel,
    val signals: List<ScamSignal>,
    val knownBad: Boolean,
)

/**
 * The owner-facing result for a whole message: the worst link decides the
 * overall level, with the reasons and a single clear next step.
 */
public data class ScamVerdict(
    val level: ScamLevel,
    val findings: List<LinkFinding>,
    /** Plain reasons, worst first, ready to show. */
    val reasons: List<String>,
    /** One recommended action for the owner. */
    val nextStep: String,
    /** Scam signals in the message text itself, independent of any link. */
    val messageSignals: List<ScamSignal> = emptyList(),
) {
    public val hasLink: Boolean get() = findings.isNotEmpty()
}

/**
 * Judges whether a message is a scam link (FR-CHK-05). It pulls links out of the
 * text, runs the on-device heuristics on each, optionally checks a privacy-
 * preserving reputation list, and returns a single [ScamVerdict] the owner can
 * act on. The verdict never silently trusts a link: it always explains why, and
 * when it names a brand it points the owner at that brand's real address.
 *
 * Everything runs on the device. The only part that may reach the network is the
 * reputation lookup, which sends a hash *prefix*, never the link (see
 * [HashPrefixChecker]).
 */
public class ScamChecker(
    private val extractor: UrlExtractor = UrlExtractor(),
    private val heuristics: ScamHeuristics = ScamHeuristics(),
    private val brands: BrandDirectory = BrandDirectory.bundled(),
    /** Optional reputation check; when null, only the on-device signals are used. */
    private val reputation: HashPrefixChecker? = null,
) {
    public fun check(messageText: String): ScamVerdict {
        val urls = extractor.extract(messageText)
        val messageSignals = messageScamSignals(messageText)
        val messageLevel = levelFromWeight(messageSignals.sumOf { it.weight })

        if (urls.isEmpty()) {
            // No link, but the text itself can still be a scam — mobile-money
            // "reverse my transfer", code requests, prize bait (security review M5).
            if (messageSignals.isEmpty()) {
                return ScamVerdict(
                    level = ScamLevel.NO_LINK,
                    findings = emptyList(),
                    reasons = emptyList(),
                    nextStep = "No link was found, and nothing in the wording stood out. Stay cautious anyway if you did not expect this message.",
                )
            }
            return ScamVerdict(
                level = messageLevel,
                findings = emptyList(),
                reasons = messageSignals.map { it.explain },
                nextStep = messageNextStep(messageLevel),
                messageSignals = messageSignals,
            )
        }

        val findings = urls.map { url -> judge(url, messageText) }
        val linkWorst = findings.minByOrNull { it.level.ordinal }!! // KNOWN_SCAM has the lowest ordinal
        // The overall level is the worst of the link verdict and the message text.
        val overall = minOf(linkWorst.level, messageLevel, compareBy { it.ordinal })
        val reasons = (
            findings
                .filter { it.level.ordinal <= ScamLevel.CAUTION.ordinal }
                .flatMap { it.signals.map { s -> s.explain } } +
                messageSignals.map { it.explain }
            ).distinct()

        return ScamVerdict(
            level = overall,
            findings = findings,
            reasons = reasons,
            nextStep = nextStep(linkWorst),
            messageSignals = messageSignals,
        )
    }

    /** Map a total signal weight to a level. Used for the message-text pass. */
    private fun levelFromWeight(sum: Int): ScamLevel = when {
        sum >= 60 -> ScamLevel.LIKELY_SCAM
        sum >= 30 -> ScamLevel.CAUTION
        else -> ScamLevel.LIKELY_SAFE
    }

    /** Non-link scam patterns common in SMS / mobile-money fraud (FR-CHK-05, M5). */
    private fun messageScamSignals(text: String): List<ScamSignal> {
        val t = text.lowercase()
        val out = mutableListOf<ScamSignal>()
        // A one-time-code message is only a scam when it asks the reader to hand
        // the code *over* to someone. A normal delivery ("your code is 482913, do
        // not share it") mentions a code and the word "share", but tells you NOT
        // to pass it on — flagging those as scams breaks the most common security
        // SMS people get (security review N5). So: a code word plus a directed
        // "send it to me" ask, and never when it reads like a plain delivery or
        // carries a do-not-share warning.
        val mentionsCode = CODE_WORD.any { t.contains(it) }
        val looksLikeDelivery = DO_NOT_SHARE.any { t.contains(it) } || OTP_DELIVERY.any { t.contains(it) }
        val asksForCode = SEND_TO_VERB.any { t.contains(it) }
        if (mentionsCode && asksForCode && !looksLikeDelivery) {
            out += ScamSignal("CODE_REQUEST", 65, "Someone is asking you to send them a one-time code or PIN. No real company or person needs your code — it is the key to your account or wallet.")
        }
        if (MONEY_REVERSAL.any { t.contains(it) }) {
            out += ScamSignal("MONEY_REVERSAL", 50, "This is the mobile-money 'wrong transfer, please send it back' trick. If you didn't receive real money, sending any back loses your own.")
        }
        if (PRIZE.any { t.contains(it) }) {
            out += ScamSignal("PRIZE_BAIT", 40, "It claims you won a prize or money. Real prizes never need you to pay a fee or share a code first.")
        }
        if (CREDENTIAL_BAIT.any { t.contains(it) }) {
            out += ScamSignal("CREDENTIAL_BAIT", 40, "It asks you to confirm a password, card or account details. Real companies don't ask for these by text; enter them only in their official app.")
        }
        if (DELIVERY_FEE.any { t.contains(it) }) {
            out += ScamSignal("ADVANCE_FEE", 35, "It asks you to pay a fee or 'release' money to receive a parcel or transfer — a common advance-fee trick. You should never pay to receive money owed to you.")
        }
        if (ACCOUNT_THREAT.any { t.contains(it) }) {
            out += ScamSignal("ACCOUNT_THREAT", 35, "It pressures you with your account being blocked or suspended, a common way to rush you into a mistake.")
        }
        if (CALLBACK.any { t.contains(it) }) {
            out += ScamSignal("CALLBACK_NUMBER", 25, "It asks you to call a number in the message. Reach your bank or operator on a number you already have, not one a message gives you.")
        }
        return out.sortedByDescending { it.weight }
    }

    private fun messageNextStep(level: ScamLevel): String = when (level) {
        ScamLevel.LIKELY_SCAM ->
            "This looks like a scam. Don't send money or share any code. If it claims to be your bank or mobile-money provider, call them on a number you already trust."
        ScamLevel.CAUTION ->
            "Be careful. Don't send money or a code because of this message, and verify with the company on a number you already have."
        else ->
            "Stay cautious, especially if you did not expect this message."
    }

    private fun judge(url: ParsedUrl, messageText: String): LinkFinding {
        val knownBad = reputation?.isKnownBad(url.registrableDomain) == true
        val signals = heuristics.inspect(url, messageText)

        val level = when {
            knownBad -> ScamLevel.KNOWN_SCAM
            signals.any { it.id == "BRAND_IN_SUBDOMAIN" || it.id == "LOOKALIKE_DOMAIN" || it.id == "AT_SIGN_SPOOF" } ->
                ScamLevel.LIKELY_SCAM
            signals.sumOf { it.weight } >= 70 -> ScamLevel.LIKELY_SCAM
            signals.sumOf { it.weight } >= 30 -> ScamLevel.CAUTION
            brands.brandForDomain(url.registrableDomain) != null -> ScamLevel.LIKELY_SAFE
            else -> ScamLevel.LIKELY_SAFE
        }
        return LinkFinding(url, level, signals, knownBad)
    }

    private fun nextStep(worst: LinkFinding): String {
        val impersonated = worst.signals
            .firstOrNull { it.id == "BRAND_IN_SUBDOMAIN" || it.id == "LOOKALIKE_DOMAIN" }
        val brandName = impersonated?.let {
            // Recover the brand from its genuine domain if we can.
            brands.all().firstOrNull { b -> it.explain.contains(b.name) }?.name
        }
        return when (worst.level) {
            ScamLevel.KNOWN_SCAM ->
                "Do not open this link. It is on a list of known scam websites. Delete the message."
            ScamLevel.LIKELY_SCAM ->
                if (brandName != null) {
                    "Don't tap this. If it really claims to be $brandName, open their official app or type their real address yourself — never through a link in a message."
                } else {
                    "Don't tap this link. If the message claims to be from a company you use, reach them through their official app or a number you already have."
                }
            ScamLevel.CAUTION ->
                "Be careful. Don't enter any password or code after tapping. When in doubt, reach the company through their official app instead."
            ScamLevel.LIKELY_SAFE ->
                "No scam signs found, but still never enter a password or one-time code because a message told you to."
            ScamLevel.NO_LINK ->
                "No link was found in this message."
        }
    }

    private companion object {
        val CODE_WORD = listOf("one-time", "one time", "otp", "verification code", "security code", "pin code", "approval code", "momo pin", "wallet pin", "digit code", "the code", "6 digit", "code we", "code i")

        // A request directed at the reader to hand the code over (the scam shape).
        // "read me", "what is the code", "confirm the code to me" etc.
        val SEND_TO_VERB = listOf(
            "send me", "send the", "send us", "send it", "send your code", "send back the code",
            "share the code", "share it with", "share with me", "tell me the", "give me the",
            "forward the", "forward me", "read me the", "what is the code", "what's the code",
            "confirm the code", "provide the code", "provide your code", "verify the code for me",
        )

        // A legitimate delivery/warning — never treat these as the reader being asked
        // for their code (review N5).
        val DO_NOT_SHARE = listOf(
            "do not share", "don't share", "dont share", "never share", "do not disclose",
            "not share it", "do not give this", "keep it secret", "we will never ask",
            "do not tell anyone",
        )
        val OTP_DELIVERY = listOf(
            "code is", "is your code", "is your verification", "is your one-time", "is your otp",
            "your otp is", "your code:", "code:", "use this code", "enter this code",
        )
        val MONEY_REVERSAL = listOf("wrong number", "sent by mistake", "reverse the", "reverse my", "send it back", "send back the", "please return", "transferred to you by mistake", "sent to you in error", "kindly reverse", "reverse the transaction")
        val PRIZE = listOf("you have won", "you won", "congratulations you", "claim your prize", "lucky winner", "cash prize", "won a promo", "promo winner", "win a ", "free iphone", "claim your reward", "receive your reward", "your reward", "a brand new car")
        val CREDENTIAL_BAIT = listOf("confirm your card", "card details", "confirm your details", "confirm your account", "reset your password", "update your payment", "update payment", "verify your account", "verify your details", "confirm your pin", "banking details", "confirm your card details")
        val DELIVERY_FEE = listOf("customs fee", "delivery fee", "clearance fee", "parcel is held", "package is held", "pay the fee", "pay a fee", "pending transfer", "release it here", "release your", "release the transfer", "shipping fee")
        val ACCOUNT_THREAT = listOf("account will be blocked", "account has been suspended", "account is blocked", "will be deactivated", "verify to avoid", "sim will be blocked", "number will be disconnected", "will be blocked", "wallet will be blocked", "blocked in 24", "account has been suspended", "suspended")
        val CALLBACK = listOf("call this number", "call me on", "call the number", "dial this", "contact us on", "call customer care on")
    }
}
