//! Matching programs against the signed indicator lists (FR-DSK-02, FR-DSK-04).

use psg_core::Indicator;

use crate::classify::normalise;

/// True if `token` starts at a word boundary of `name`, ignoring spaces and
/// punctuation: "ScreenConnect Client" matches "screenconnect" and
/// "connectclient", but "Lateral Tools" does not match "atera".
pub fn name_matches(name: &str, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let token = normalise(token);
    let words: Vec<String> = split_words(name);
    (0..words.len()).any(|i| words[i..].concat().starts_with(&token))
}

/// Split on non-alphanumerics and on lower-to-upper case changes, so both
/// "Any Desk" and "AnyDesk" give words that concatenate to "anydesk".
fn split_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        current.extend(c.to_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Why a program matched an indicator, for the evidence card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchReason {
    Name(String),
    Publisher(String),
    Hash(String),
}

impl MatchReason {
    pub fn describe(&self) -> String {
        match self {
            MatchReason::Name(t) => format!("name matches \"{t}\""),
            MatchReason::Publisher(p) => format!("publisher matches \"{p}\""),
            MatchReason::Hash(h) => format!("file hash {h}"),
        }
    }
}

/// Check one program against one indicator.
pub fn match_indicator(
    indicator: &Indicator,
    names: &[&str],
    publisher: &str,
    sha256: Option<&str>,
) -> Option<MatchReason> {
    if let Some(h) = sha256 {
        let h = h.to_lowercase();
        if indicator.sha256.contains(&h) {
            return Some(MatchReason::Hash(h));
        }
    }
    for token in &indicator.names {
        if names.iter().any(|n| name_matches(n, token)) {
            return Some(MatchReason::Name(token.clone()));
        }
    }
    // Publishers match at word starts too, so "Lateral Games" is not Atera.
    if !publisher.is_empty() {
        for p in &indicator.publishers {
            if name_matches(publisher, p) {
                return Some(MatchReason::Publisher(p.clone()));
            }
        }
    }
    None
}

/// True if a service name belongs to the indicator's unattended-access services.
pub fn service_matches(indicator: &Indicator, service_name: &str) -> bool {
    let s = normalise(service_name);
    indicator.services.iter().any(|t| s.starts_with(&normalise(t)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_at_word_starts_only() {
        assert!(name_matches("AnyDesk", "anydesk"));
        assert!(name_matches("Any Desk", "anydesk"));
        assert!(name_matches("ScreenConnect Client (6f1c)", "screenconnect"));
        assert!(name_matches("Chrome Remote Desktop Host", "chromeremotedesktop"));
        assert!(name_matches("AteraAgent", "atera"));
        assert!(!name_matches("Lateral Tools", "atera"));
        assert!(!name_matches("Supremely Good Notes", "supremo"));
        assert!(name_matches("Spyrix Free Keylogger", "spyrix"));
        assert!(name_matches("TeamViewer 15", "teamviewer"));
    }

    #[test]
    fn matches_by_hash_then_name_then_publisher() {
        let ind = Indicator {
            id: "RA-X".into(),
            name: "X".into(),
            names: vec!["xremote".into()],
            publishers: vec!["x remote ltd".into()],
            sha256: vec!["ab".repeat(32)],
            services: vec!["xremotesvc".into()],
            removal: String::new(),
        };
        assert_eq!(
            match_indicator(&ind, &["renamed.exe"], "", Some(&"AB".repeat(32))),
            Some(MatchReason::Hash("ab".repeat(32)))
        );
        assert_eq!(match_indicator(&ind, &["XRemote Host"], "", None), Some(MatchReason::Name("xremote".into())));
        assert_eq!(
            match_indicator(&ind, &["host.exe"], "X Remote Ltd.", None),
            Some(MatchReason::Publisher("x remote ltd".into()))
        );
        assert_eq!(match_indicator(&ind, &["Notepad"], "Microsoft", None), None);
        assert_eq!(match_indicator(&ind, &["Notepad"], "Max Remote Ltd", None), None, "publisher word starts only");
        assert!(service_matches(&ind, "XRemoteSvc_1234"));
        assert!(!service_matches(&ind, "Spooler"));
    }
}
