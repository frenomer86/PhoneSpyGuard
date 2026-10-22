//! Finds and normalises links inside a message. Scam texts routinely disguise
//! links (`hxxp`, `paypal[.]com`, spaces, zero-width characters, a
//! trusted-looking name before an `@`), so the text is de-obfuscated into plain
//! URLs first, then each is parsed into a [`ParsedUrl`]. Nothing here contacts
//! the link. Port of the phone app's `UrlExtractor`, kept rule for rule.

use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

/// A single link pulled out of a message, broken into the parts the scam
/// checks look at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedUrl {
    /// The link as it appeared in the message, after de-obfuscation.
    pub raw: String,
    pub scheme: String,
    /// The host, lower-cased.
    pub host: String,
    /// The registrable domain (eTLD+1), e.g. `paypal.com` for `login.paypal.com`.
    pub registrable_domain: String,
    /// The labels in front of the registrable domain.
    pub subdomains: Vec<String>,
    pub path: String,
    /// The host is a bare IPv4/IPv6 literal instead of a name.
    pub is_ip_host: bool,
    /// A label is IDNA punycode (`xn--`), a common look-alike trick.
    pub is_punycode: bool,
    /// The user-info part before an `@`, e.g. `paypal.com` in `paypal.com@evil.ru`.
    pub user_info: Option<String>,
}

/// A compact public-suffix set: enough to split the registrable domain out of
/// a host for the scam checks without shipping the full Public Suffix List.
/// An unknown suffix falls back to the last two labels, which is safe for the
/// look-alike and brand checks.
const PUBLIC_SUFFIXES: &[&str] = &[
    "com", "net", "org", "info", "biz", "io", "co", "app", "dev", "xyz", "top", "site", "online", "shop",
    "store", "link", "live", "me", "tv", "cc", "ru", "cn", "de", "fr", "nl", "uk", "us", "ca", "au", "in",
    "br", "za", "ng", "gh", "ke", "ug", "tz", "zip", "mov", "tk", "ml", "ga", "cf", "gq", "pw", "work",
    "click", "fit",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "com.gh", "org.gh", "gov.gh", "edu.gh", "com.ng",
    "org.ng", "gov.ng", "co.za", "org.za", "gov.za", "co.ke", "or.ke", "go.ke", "com.au", "net.au",
    "org.au", "gov.au", "co.in", "net.in", "org.in", "gov.in", "com.br", "gov.br", "co.jp", "or.jp",
    "ne.jp", "com.cn", "gov.cn", "com.tr", "com.mx", "com.ar", "com.sg", "com.hk",
];

const TRAILING_PUNCT: &[char] = &['.', ',', ')', ']', '}', '"', '\'', '!', '?', ';', ':'];

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("built-in pattern"))
}

macro_rules! pattern {
    ($name:ident, $p:expr) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            re(&CELL, $p)
        }
    };
}

pattern!(scheme_re, r"^([a-zA-Z][a-zA-Z0-9+.-]*)://");
pattern!(ipv4_re, r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$");
// A link candidate: optional scheme, a dotted host, optional path. Also
// matches bare domains like `paypal-secure.com/login`. Word characters are
// ASCII, as on the phone.
pattern!(
    candidate_re,
    r"((?:[a-zA-Z][a-zA-Z0-9+.-]*://)?(?:[^\s/@]+@)?(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)(?::[0-9]+)?(?:/[^\s]*)?)"
);
pattern!(hidden_re, "[\u{200B}-\u{200F}\u{202A}-\u{202E}\u{2060}\u{FEFF}]");
pattern!(hxxp_re, r"(?i)h(?:xx|tt)p(s?)://");
pattern!(hxxp_start_re, r"(?i)^\s*hxxp");
pattern!(bracket_dot_re, r"\s*[\[(\{]\s*\.\s*[\])\}]\s*");
pattern!(word_dot_re, r"(?i)\s+dot\s+");
pattern!(bracket_colon_re, r"[\[(\{]\s*:\s*[\])\}]");
pattern!(bracket_at_re, r"[\[(\{]\s*@\s*[\])\}]");

/// Undo the common ways scammers break a URL so filters miss it.
pub fn deobfuscate(text: &str) -> String {
    let s = hidden_re().replace_all(text, "");
    let s = hxxp_re().replace_all(&s, "http$1://");
    let s = hxxp_start_re().replace_all(&s, "http");
    let s = bracket_dot_re().replace_all(&s, ".");
    let s = word_dot_re().replace_all(&s, ".");
    let s = bracket_colon_re().replace_all(&s, ":");
    let s = bracket_at_re().replace_all(&s, "@");
    s.into_owned()
}

/// Every distinct link in `message`, in the order they appear.
pub fn extract(message: &str) -> Vec<ParsedUrl> {
    let cleaned = deobfuscate(message);
    let mut out: Vec<ParsedUrl> = Vec::new();
    for m in candidate_re().find_iter(&cleaned) {
        let token = m.as_str().trim().trim_end_matches(TRAILING_PUNCT);
        let Some(parsed) = parse(token) else { continue };
        // The same link counts once.
        if !out.iter().any(|u| u.raw == parsed.raw) {
            out.push(parsed);
        }
    }
    out
}

/// Parse one already-isolated link, or `None` if it is not a usable URL.
pub fn parse(token: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = match scheme_re().captures(token) {
        Some(c) => (c[1].to_lowercase(), &token[c[0].len()..]),
        None => ("http".to_string(), token),
    };
    let authority_end = rest.find(['/', '?', '#']);
    let (authority, path) = match authority_end {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // The `@` host-spoof trick: everything before the last `@` is user-info.
    let (user_info, host_part) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    let host_part = strip_port(host_part);
    if host_part.is_empty() {
        return None;
    }
    let host = host_part.to_lowercase();
    let is_ip = ipv4_re().is_match(&host) || host.starts_with('[');
    let is_punycode = host.split('.').any(|l| l.starts_with("xn--"));
    // A plain word with no dot is not a link.
    if !is_ip && !host.contains('.') {
        return None;
    }
    let (registrable_domain, subdomains) = if is_ip { (host.clone(), Vec::new()) } else { registrable(&host) };
    Some(ParsedUrl {
        raw: token.to_string(),
        scheme,
        host,
        registrable_domain,
        subdomains,
        path: path.to_string(),
        is_ip_host: is_ip,
        is_punycode,
        user_info: user_info.filter(|u| !u.is_empty()).map(str::to_string),
    })
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return match host.find(']') {
            Some(close) => &host[..=close],
            None => host,
        };
    }
    match host.find(':') {
        Some(colon) => &host[..colon],
        None => host,
    }
}

/// Split a host into (registrable domain, subdomain labels).
fn registrable(host: &str) -> (String, Vec<String>) {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 1 {
        return (host.to_string(), Vec::new());
    }
    // The longest public suffix that matches the tail.
    let mut suffix_len = 1;
    for len in (1..=(labels.len() - 1).min(3)).rev() {
        if PUBLIC_SUFFIXES.contains(&labels[labels.len() - len..].join(".").as_str()) {
            suffix_len = len;
            break;
        }
    }
    let registrable_len = suffix_len + 1;
    if labels.len() <= registrable_len {
        return (host.to_string(), Vec::new());
    }
    let split = labels.len() - registrable_len;
    (labels[split..].join("."), labels[..split].iter().map(|s| s.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_plain_url() {
        let urls = extract("Please visit https://login.paypal.com/secure now");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].registrable_domain, "paypal.com");
        assert_eq!(urls[0].subdomains, vec!["login"]);
        assert_eq!(urls[0].path, "/secure");
    }

    #[test]
    fn finds_a_bare_domain_without_scheme() {
        let urls = extract("go to paypal-secure.com/login");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].registrable_domain, "paypal-secure.com");
        assert_eq!(urls[0].scheme, "http");
    }

    #[test]
    fn undoes_bracket_dots_and_hxxp() {
        let urls = extract("tap hxxps://paypal[.]com[.]secure[.]ru to fix");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].registrable_domain, "secure.ru");
    }

    #[test]
    fn handles_dot_spelled_out() {
        let urls = extract("open evil dot example dot com please");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].registrable_domain, "example.com");
    }

    #[test]
    fn spots_an_ip_host() {
        let urls = extract("http://203.0.113.9/login");
        assert_eq!(urls.len(), 1);
        assert!(urls[0].is_ip_host);
        assert_eq!(urls[0].registrable_domain, "203.0.113.9");
    }

    #[test]
    fn spots_user_info_before_an_at_sign() {
        let urls = extract("http://paypal.com@evil.ru/go");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].registrable_domain, "evil.ru");
        assert_eq!(urls[0].user_info.as_deref(), Some("paypal.com"));
    }

    #[test]
    fn multi_label_suffixes_give_the_right_domain() {
        let urls = extract("see secure.mtn.com.gh/wallet");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].registrable_domain, "mtn.com.gh");
        assert_eq!(urls[0].subdomains, vec!["secure"]);
    }

    #[test]
    fn flags_punycode() {
        let urls = extract("https://xn--pypal-4ve.com/login");
        assert_eq!(urls.len(), 1);
        assert!(urls[0].is_punycode);
    }

    #[test]
    fn plain_words_are_not_links() {
        assert!(extract("call me tomorrow about the thing").is_empty());
    }

    #[test]
    fn strips_trailing_punctuation() {
        assert_eq!(extract("is this real: paypal-secure.com.")[0].registrable_domain, "paypal-secure.com");
    }

    #[test]
    fn counts_a_repeated_link_once() {
        assert_eq!(extract("paypal.com paypal.com paypal.com").len(), 1);
    }

    #[test]
    fn strips_zero_width_characters() {
        let urls = extract("pay\u{200B}pal-secure.com/login");
        assert_eq!(urls[0].registrable_domain, "paypal-secure.com");
    }
}
