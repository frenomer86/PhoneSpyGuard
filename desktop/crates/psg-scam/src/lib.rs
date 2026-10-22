//! The message check: is a pasted text, chat message or email a scam? It pulls
//! the links out of the text, runs the on-PC checks on each and on the wording
//! itself, and returns one [`ScamVerdict`] the owner can act on. It always
//! says why, and when it names a brand it points at that brand's real address.
//!
//! This is the phone app's checker (`core/scam`), ported rule for rule with the
//! same brand list and the same labelled test messages, so a message gets the
//! same answer on the PC as on the phone. Nothing is sent anywhere: the phone's
//! optional reputation lookup is left out, as the desktop app's only network
//! use is downloading signed rules.

pub mod url;

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

pub use url::ParsedUrl;

/// How dangerous a message is. Ordered worst first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScamLevel {
    /// Impersonates a real brand, or trips several strong signals.
    LikelyScam,
    /// Some warning signs, not conclusive.
    Caution,
    /// A genuine brand domain, or nothing suspicious found.
    LikelySafe,
    /// No link and nothing in the wording.
    NoLink,
}

/// One reason a link or message looks like a scam, and how much it weighs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScamSignal {
    pub id: &'static str,
    /// 0..100; higher is more incriminating.
    pub weight: u32,
    /// A plain reason the owner can read.
    pub explain: String,
}

fn signal(id: &'static str, weight: u32, explain: impl Into<String>) -> ScamSignal {
    ScamSignal { id, weight, explain: explain.into() }
}

/// The finding for one link.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkFinding {
    pub url: ParsedUrl,
    pub level: ScamLevel,
    pub signals: Vec<ScamSignal>,
}

/// The result for a whole message: the worst of its links and its wording.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScamVerdict {
    pub level: ScamLevel,
    pub findings: Vec<LinkFinding>,
    /// Plain reasons, worst first.
    pub reasons: Vec<String>,
    /// One recommended action.
    pub next_step: String,
    /// Signals in the wording itself, independent of any link.
    pub message_signals: Vec<ScamSignal>,
}

impl ScamVerdict {
    pub fn has_link(&self) -> bool {
        !self.findings.is_empty()
    }
}

// --- brands -------------------------------------------------------------------

/// A brand a scam is likely to impersonate, and the domains it really uses.
#[derive(Debug, Clone, Deserialize)]
pub struct Brand {
    pub name: String,
    pub aliases: Vec<String>,
    pub domains: Vec<String>,
}

#[derive(Deserialize)]
struct BrandFile {
    brands: Vec<Brand>,
}

/// The bundled brand list, the same file as the phone app's.
pub fn brands() -> &'static [Brand] {
    static BRANDS: OnceLock<Vec<Brand>> = OnceLock::new();
    BRANDS.get_or_init(|| {
        serde_json::from_str::<BrandFile>(include_str!("../data/brand-directory.json"))
            .expect("bundled brand directory")
            .brands
    })
}

fn brand_for_domain(domain: &str) -> Option<&'static Brand> {
    brands().iter().find(|b| b.domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))
}

fn brand_for_alias(token: &str) -> Option<&'static Brand> {
    let t = token.to_lowercase();
    brands().iter().find(|b| b.aliases.contains(&t))
}

// --- link checks ------------------------------------------------------------------

const RISKY_TLDS: &[&str] = &["zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "click", "fit", "work"];
const SHORTENERS: &[&str] = &["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"];
const CREDENTIAL_WORDS: &[&str] = &["login", "log-in", "signin", "sign-in", "verify", "secure", "account", "update", "confirm", "webscr", "unlock", "wallet", "password", "otp"];
const URGENCY_WORDS: &[&str] = &["urgent", "immediately", "suspend", "blocked", "within 24", "expire", "verify now", "you have won", "you won", "prize", "refund", "claim now", "account locked", "final notice"];

fn after_last_dot(s: &str) -> &str {
    s.rsplit_once('.').map_or(s, |(_, t)| t)
}

fn before_last_dot(s: &str) -> &str {
    s.rsplit_once('.').map_or(s, |(h, _)| h)
}

fn any_in(text: &str, words: &[&str]) -> bool {
    words.iter().any(|w| text.contains(w))
}

/// Every signal a link trips, strongest first. The message text adds context
/// for urgency wording. Conservative: one weak signal is a caution, and brand
/// impersonation is called only when someone else's domain clearly imitates a
/// real brand.
pub fn inspect_link(url: &ParsedUrl, message_text: &str) -> Vec<ScamSignal> {
    let mut out = Vec::new();
    if url.is_ip_host {
        out.push(signal("RAW_IP_HOST", 55, "The link points at a raw IP address, not a named website. Real companies don't send links like this."));
    }
    if url.is_punycode {
        out.push(signal("PUNYCODE_HOST", 60, "The web address uses look-alike foreign letters to imitate a real name."));
    }
    if let Some(user) = url.user_info.as_deref().filter(|u| u.contains('.')) {
        out.push(signal("AT_SIGN_SPOOF", 65, format!("A trusted-looking name sits before an '@', which hides the real site (\"{user}\" is not where this goes).")));
    }
    if url.subdomains.len() >= 4 {
        out.push(signal("MANY_SUBDOMAINS", 35, "The address is padded with many parts to look longer and more official than it is."));
    }
    let tld = after_last_dot(&url.registrable_domain);
    if RISKY_TLDS.contains(&tld) {
        out.push(signal("RISKY_TLD", 30, format!("The address ends in \".{tld}\", an ending heavily abused for scams.")));
    }
    if SHORTENERS.contains(&url.registrable_domain.as_str()) {
        out.push(signal("URL_SHORTENER", 30, "It's a shortened link, so you can't see where it really leads until you open it."));
    }
    if any_in(&format!("{}{}", url.host, url.path).to_lowercase(), CREDENTIAL_WORDS) {
        out.push(signal("CREDENTIAL_BAIT", 30, "The link talks about logging in, verifying or securing your account — classic bait to steal your password."));
    }
    if url.host.matches('-').count() >= 3 {
        out.push(signal("DASH_STUFFED", 20, "The address is stuffed with dashes to cram a brand name into someone else's site."));
    }
    if let Some(s) = brand_impersonation(url) {
        out.push(s);
    }
    if any_in(&message_text.to_lowercase(), URGENCY_WORDS) {
        out.push(signal("URGENCY_PRESSURE", 15, "The message pressures you to act fast or claims something will be lost — a standard scam tactic."));
    }
    // Stable, so equal weights keep the order they were found in.
    out.sort_by_key(|s| std::cmp::Reverse(s.weight));
    out
}

fn brand_impersonation(url: &ParsedUrl) -> Option<ScamSignal> {
    // A domain the brand really owns is not impersonation.
    if brand_for_domain(&url.registrable_domain).is_some() {
        return None;
    }
    // A brand name used as a subdomain of someone else's domain.
    for sub in &url.subdomains {
        if let Some(brand) = brand_for_alias(sub) {
            return Some(signal(
                "BRAND_IN_SUBDOMAIN",
                70,
                format!("This looks like {0}, but the real website is \"{1}\", which {0} does not own.", brand.name, url.registrable_domain),
            ));
        }
    }
    // A near look-alike of a real brand domain.
    let core = before_last_dot(&url.registrable_domain);
    for brand in brands() {
        for domain in &brand.domains {
            let brand_core = before_last_dot(domain);
            if core == brand_core {
                continue;
            }
            if looks_like(core, brand_core) {
                return Some(signal(
                    "LOOKALIKE_DOMAIN",
                    68,
                    format!("\"{}\" is a near-copy of {}'s real address \"{domain}\" — one or two letters changed to fool the eye.", url.registrable_domain, brand.name),
                ));
            }
        }
    }
    None
}

/// One edit away from a name of real length, or a digit-for-letter swap.
fn looks_like(a: &str, b: &str) -> bool {
    if b.chars().count() < 4 {
        return false;
    }
    let normalised: String = a
        .chars()
        .map(|c| match c {
            '1' => 'l',
            '0' => 'o',
            '3' => 'e',
            '5' => 's',
            '4' => 'a',
            '7' => 't',
            '$' => 's',
            other => other,
        })
        .collect();
    normalised == b || edit_distance_at_most_one(a, b)
}

fn edit_distance_at_most_one(a: &str, b: &str) -> bool {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    let (mut i, mut j, mut edits) = (0, 0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            i += 1;
            j += 1;
            continue;
        }
        edits += 1;
        if edits > 1 {
            return false;
        }
        if a.len() > b.len() {
            i += 1;
        } else if a.len() < b.len() {
            j += 1;
        } else {
            i += 1;
            j += 1;
        }
    }
    edits + (a.len() - i) + (b.len() - j) <= 1
}

// --- wording checks -------------------------------------------------------------------

const CODE_WORD: &[&str] = &["one-time", "one time", "otp", "verification code", "security code", "pin code", "approval code", "momo pin", "wallet pin", "digit code", "the code", "6 digit", "code we", "code i"];
// A request aimed at the reader to hand the code over: the scam shape.
const SEND_TO_VERB: &[&str] = &[
    "send me", "send the", "send us", "send it", "send your code", "send back the code", "share the code", "share it with",
    "share with me", "tell me the", "give me the", "forward the", "forward me", "read me the", "what is the code",
    "what's the code", "confirm the code", "provide the code", "provide your code", "verify the code for me",
];
// A genuine code delivery or warning: never the reader being asked for a code.
const DO_NOT_SHARE: &[&str] = &["do not share", "don't share", "dont share", "never share", "do not disclose", "not share it", "do not give this", "keep it secret", "we will never ask", "do not tell anyone"];
const OTP_DELIVERY: &[&str] = &["code is", "is your code", "is your verification", "is your one-time", "is your otp", "your otp is", "your code:", "code:", "use this code", "enter this code"];
const MONEY_REVERSAL: &[&str] = &["wrong number", "sent by mistake", "reverse the", "reverse my", "send it back", "send back the", "please return", "transferred to you by mistake", "sent to you in error", "kindly reverse", "reverse the transaction"];
const PRIZE: &[&str] = &["you have won", "you won", "congratulations you", "claim your prize", "lucky winner", "cash prize", "won a promo", "promo winner", "win a ", "free iphone", "claim your reward", "receive your reward", "your reward", "a brand new car"];
const CREDENTIAL_BAIT: &[&str] = &["confirm your card", "card details", "confirm your details", "confirm your account", "reset your password", "update your payment", "update payment", "verify your account", "verify your details", "confirm your pin", "banking details", "confirm your card details"];
const DELIVERY_FEE: &[&str] = &["customs fee", "delivery fee", "clearance fee", "parcel is held", "package is held", "pay the fee", "pay a fee", "pending transfer", "release it here", "release your", "release the transfer", "shipping fee"];
const ACCOUNT_THREAT: &[&str] = &["account will be blocked", "account has been suspended", "account is blocked", "will be deactivated", "verify to avoid", "sim will be blocked", "number will be disconnected", "will be blocked", "wallet will be blocked", "blocked in 24", "suspended"];
const CALLBACK: &[&str] = &["call this number", "call me on", "call the number", "dial this", "contact us on", "call customer care on"];

/// Scam patterns in the wording itself: code requests, mobile-money reversal,
/// prize bait and the rest. Strongest first.
pub fn inspect_message(text: &str) -> Vec<ScamSignal> {
    let t = text.to_lowercase();
    let mut out = Vec::new();
    // A code message is only a scam when it asks the reader to hand the code
    // over. A normal delivery ("your code is 482913, do not share it") must
    // never be flagged: it is the most common security text people get.
    let looks_like_delivery = any_in(&t, DO_NOT_SHARE) || any_in(&t, OTP_DELIVERY);
    if any_in(&t, CODE_WORD) && any_in(&t, SEND_TO_VERB) && !looks_like_delivery {
        out.push(signal("CODE_REQUEST", 65, "Someone is asking you to send them a one-time code or PIN. No real company or person needs your code — it is the key to your account or wallet."));
    }
    if any_in(&t, MONEY_REVERSAL) {
        out.push(signal("MONEY_REVERSAL", 50, "This is the mobile-money 'wrong transfer, please send it back' trick. If you didn't receive real money, sending any back loses your own."));
    }
    if any_in(&t, PRIZE) {
        out.push(signal("PRIZE_BAIT", 40, "It claims you won a prize or money. Real prizes never need you to pay a fee or share a code first."));
    }
    if any_in(&t, CREDENTIAL_BAIT) {
        out.push(signal("CREDENTIAL_BAIT", 40, "It asks you to confirm a password, card or account details. Real companies don't ask for these by message; enter them only in their official app or website."));
    }
    if any_in(&t, DELIVERY_FEE) {
        out.push(signal("ADVANCE_FEE", 35, "It asks you to pay a fee or 'release' money to receive a parcel or transfer — a common advance-fee trick. You should never pay to receive money owed to you."));
    }
    if any_in(&t, ACCOUNT_THREAT) {
        out.push(signal("ACCOUNT_THREAT", 35, "It pressures you with your account being blocked or suspended, a common way to rush you into a mistake."));
    }
    if any_in(&t, CALLBACK) {
        out.push(signal("CALLBACK_NUMBER", 25, "It asks you to call a number in the message. Reach your bank or operator on a number you already have, not one a message gives you."));
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.weight));
    out
}

fn level_from_weight(sum: u32) -> ScamLevel {
    match sum {
        60.. => ScamLevel::LikelyScam,
        30.. => ScamLevel::Caution,
        _ => ScamLevel::LikelySafe,
    }
}

fn is_impersonation(id: &str) -> bool {
    id == "BRAND_IN_SUBDOMAIN" || id == "LOOKALIKE_DOMAIN"
}

fn judge(url: ParsedUrl, message_text: &str) -> LinkFinding {
    let signals = inspect_link(&url, message_text);
    let sum: u32 = signals.iter().map(|s| s.weight).sum();
    let level = if signals.iter().any(|s| is_impersonation(s.id) || s.id == "AT_SIGN_SPOOF") || sum >= 70 {
        ScamLevel::LikelyScam
    } else if sum >= 30 {
        ScamLevel::Caution
    } else {
        ScamLevel::LikelySafe
    };
    LinkFinding { url, level, signals }
}

fn link_next_step(worst: &LinkFinding) -> String {
    let brand = worst
        .signals
        .iter()
        .find(|s| is_impersonation(s.id))
        .and_then(|s| brands().iter().find(|b| s.explain.contains(&b.name)));
    match (worst.level, brand) {
        (ScamLevel::LikelyScam, Some(b)) => format!(
            "Don't open this. If it really claims to be {}, open their official app or type their real address yourself — never through a link in a message.",
            b.name
        ),
        (ScamLevel::LikelyScam, None) => "Don't open this link. If the message claims to be from a company you use, reach them through their official app or a number you already have.".into(),
        (ScamLevel::Caution, _) => "Be careful. Don't enter any password or code after opening it. When in doubt, reach the company through their official app instead.".into(),
        (ScamLevel::LikelySafe, _) => "No scam signs found, but still never enter a password or one-time code because a message told you to.".into(),
        (ScamLevel::NoLink, _) => "No link was found in this message.".into(),
    }
}

fn message_next_step(level: ScamLevel) -> String {
    match level {
        ScamLevel::LikelyScam => "This looks like a scam. Don't send money or share any code. If it claims to be your bank or mobile-money provider, call them on a number you already trust.",
        ScamLevel::Caution => "Be careful. Don't send money or a code because of this message, and verify with the company on a number you already have.",
        _ => "Stay cautious, especially if you did not expect this message.",
    }
    .into()
}

/// Judge a pasted message.
pub fn check(message_text: &str) -> ScamVerdict {
    let urls = url::extract(message_text);
    let message_signals = inspect_message(message_text);
    let message_level = level_from_weight(message_signals.iter().map(|s| s.weight).sum());

    if urls.is_empty() {
        if message_signals.is_empty() {
            return ScamVerdict {
                level: ScamLevel::NoLink,
                findings: Vec::new(),
                reasons: Vec::new(),
                next_step: "No link was found, and nothing in the wording stood out. Stay cautious anyway if you did not expect this message.".into(),
                message_signals,
            };
        }
        return ScamVerdict {
            level: message_level,
            findings: Vec::new(),
            reasons: message_signals.iter().map(|s| s.explain.clone()).collect(),
            next_step: message_next_step(message_level),
            message_signals,
        };
    }

    let findings: Vec<LinkFinding> = urls.into_iter().map(|u| judge(u, message_text)).collect();
    // The first of the worst links, as on the phone.
    let worst = findings.iter().fold(&findings[0], |w, f| if f.level < w.level { f } else { w });
    let mut reasons: Vec<String> = Vec::new();
    let link_reasons = findings.iter().filter(|f| f.level <= ScamLevel::Caution).flat_map(|f| f.signals.iter());
    for r in link_reasons.chain(message_signals.iter()).map(|s| &s.explain) {
        if !reasons.contains(r) {
            reasons.push(r.clone());
        }
    }
    ScamVerdict {
        level: worst.level.min(message_level),
        next_step: link_next_step(worst),
        findings: findings.clone(),
        reasons,
        message_signals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(v: &[ScamSignal], id: &str) -> bool {
        v.iter().any(|s| s.id == id)
    }

    #[test]
    fn a_genuine_brand_domain_is_safe() {
        assert_eq!(check("Your receipt is at https://www.paypal.com/activity").level, ScamLevel::LikelySafe);
    }

    #[test]
    fn a_brand_in_a_subdomain_is_likely_a_scam() {
        let v = check("Confirm your account: http://paypal.secure-login.ru/verify");
        assert_eq!(v.level, ScamLevel::LikelyScam);
        assert!(has(&v.findings[0].signals, "BRAND_IN_SUBDOMAIN"));
        assert!(v.next_step.contains("PayPal"));
    }

    #[test]
    fn a_lookalike_domain_is_likely_a_scam() {
        let v = check("Login needed: https://paypa1.com/signin");
        assert_eq!(v.level, ScamLevel::LikelyScam);
        assert!(has(&v.findings[0].signals, "LOOKALIKE_DOMAIN"));
    }

    #[test]
    fn an_at_sign_spoof_is_likely_a_scam() {
        assert_eq!(check("Update here http://apple.com@198.51.100.7/id").level, ScamLevel::LikelyScam);
    }

    #[test]
    fn momo_impersonation_is_caught() {
        let v = check("MTN: your MoMo wallet is blocked, verify at mtn.momo-unlock.top/verify within 24 hours");
        assert_eq!(v.level, ScamLevel::LikelyScam);
        assert!(!v.reasons.is_empty());
    }

    #[test]
    fn mild_signals_are_a_caution() {
        assert_eq!(check("here you go: https://bit.ly/3xYz").level, ScamLevel::Caution);
    }

    #[test]
    fn no_link_and_plain_wording_is_no_link() {
        let v = check("Hey, are we still on for lunch?");
        assert_eq!(v.level, ScamLevel::NoLink);
        assert!(!v.has_link());
    }

    #[test]
    fn a_momo_reversal_without_a_link_is_flagged() {
        let v = check("Hello, I sent GHS 500 to your number by mistake, please kindly reverse the transaction to me.");
        assert_eq!(v.level, ScamLevel::Caution);
        assert!(has(&v.message_signals, "MONEY_REVERSAL"));
        assert!(!v.has_link());
    }

    #[test]
    fn a_code_request_without_a_link_is_likely_a_scam() {
        let v = check("This is MTN customer care. Please send the one-time code we just texted you to confirm your wallet.");
        assert_eq!(v.level, ScamLevel::LikelyScam);
        assert!(has(&v.message_signals, "CODE_REQUEST"));
    }

    #[test]
    fn a_genuine_code_delivery_is_not_flagged() {
        for sms in [
            "Your verification code is 482913. Do not share it with anyone.",
            "G-558213 is your Google verification code.",
            "123456 is your OTP. Never share this code. - MTN MoMo",
            "Use this code 904521 to log in. We will never ask you for it.",
        ] {
            let v = check(sms);
            assert!(!has(&v.message_signals, "CODE_REQUEST"), "false positive on: {sms}");
            assert_ne!(v.level, ScamLevel::LikelyScam, "wrongly a scam: {sms}");
        }
    }

    #[test]
    fn asking_for_your_code_is_flagged() {
        let v = check("MoMo security: please send me the one-time code we just sent you to verify your wallet.");
        assert!(has(&v.message_signals, "CODE_REQUEST"));
    }

    #[test]
    fn the_wording_can_raise_a_link_verdict() {
        let v = check("Congratulations you won a cash prize! Your account will be blocked unless you claim at https://bit.ly/abc");
        assert_eq!(v.level, ScamLevel::LikelyScam);
        assert!(!v.message_signals.is_empty());
    }

    #[test]
    fn the_worst_link_decides() {
        let v = check("Two links: https://www.apple.com/ and http://apple.secure-id.ru/verify");
        assert_eq!(v.level, ScamLevel::LikelyScam);
        assert_eq!(v.findings.len(), 2);
    }

    #[test]
    fn a_raw_ip_and_credential_bait_add_up() {
        assert_eq!(check("http://203.0.113.9/account/login/verify").level, ScamLevel::LikelyScam);
    }

    #[test]
    fn the_brand_list_loads() {
        assert!(brands().len() >= 10);
        assert!(brand_for_domain("mtn.com.gh").is_some());
    }
}
