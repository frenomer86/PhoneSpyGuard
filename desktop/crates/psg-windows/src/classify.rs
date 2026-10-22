//! Pure helpers that turn raw Windows values into facts. Kept free of any OS
//! calls so they are unit-tested on every platform.

use std::net::Ipv4Addr;

/// Lower-case and keep only letters and digits, so "Any Desk", "AnyDesk.exe"
/// and "anydesk_service" all contain "anydesk".
pub fn normalise(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

/// The last path component, without extension, normalised.
pub fn file_stem_normalised(path: &str) -> String {
    let file = path.rsplit(['\\', '/']).next().unwrap_or(path);
    let stem = file.rsplit_once('.').map(|(s, _)| s).unwrap_or(file);
    normalise(stem)
}

/// True when a standard user (and so any program they run) can write to the
/// folder: anything under a user profile, ProgramData, or a temp folder.
pub fn is_user_writable_path(path: &str) -> bool {
    let p = path.to_lowercase().replace('/', "\\");
    let p = p.trim_start_matches("\\\\?\\").trim_start_matches("\\??\\");
    let after_drive = p.get(2..).unwrap_or("");
    after_drive.starts_with("\\users\\")
        || after_drive.starts_with("\\programdata\\")
        || after_drive.starts_with("\\windows\\temp\\")
        || after_drive.starts_with("\\temp\\")
        || after_drive.starts_with("\\tmp\\")
}

/// Pull the program path out of an autostart command line.
///
/// Handles quoted paths, unquoted paths with spaces (by trying ever longer
/// prefixes that end in an executable extension), `rundll32 dll,Entry`, NT
/// prefixes (`\??\`, `\SystemRoot\`) and a bare `System32\...`. Environment
/// variables are expanded by `expand`. Returns None for an empty command.
pub fn executable_from_command(command: &str, expand: &dyn Fn(&str) -> String) -> Option<String> {
    let expanded = expand(command.trim());
    let cmd = expanded.trim();
    if cmd.is_empty() {
        return None;
    }

    let (first, rest) = if let Some(stripped) = cmd.strip_prefix('"') {
        match stripped.find('"') {
            Some(end) => (stripped[..end].to_string(), stripped[end + 1..].trim().to_string()),
            None => (stripped.to_string(), String::new()),
        }
    } else {
        split_unquoted(cmd)
    };

    let first = fix_nt_path(&first);
    let stem = file_stem_normalised(&first);
    if stem == "rundll32" {
        // rundll32 "C:\x\y.dll",Entry  ->  the DLL is what runs.
        let arg = rest.trim().trim_start_matches('"');
        let dll = arg.split([',', '"']).next().unwrap_or("").trim();
        if !dll.is_empty() {
            return Some(fix_nt_path(dll));
        }
    }
    Some(first)
}

fn split_unquoted(cmd: &str) -> (String, String) {
    const EXTS: [&str; 7] = [".exe", ".dll", ".com", ".bat", ".cmd", ".scr", ".sys"];
    let lower = cmd.to_lowercase();
    for ext in EXTS {
        let mut search = 0;
        while let Some(pos) = lower[search..].find(ext) {
            let end = search + pos + ext.len();
            if end == cmd.len() || cmd[end..].starts_with(' ') || cmd[end..].starts_with(',') {
                return (cmd[..end].to_string(), cmd[end..].trim().to_string());
            }
            search = end;
        }
    }
    match cmd.split_once(' ') {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => (cmd.to_string(), String::new()),
    }
}

fn fix_nt_path(p: &str) -> String {
    let p = p.trim();
    if let Some(rest) = p.strip_prefix("\\??\\") {
        return rest.to_string();
    }
    let lower = p.to_lowercase();
    if lower.starts_with("\\systemroot\\") {
        return format!("C:\\Windows{}", &p["\\systemroot".len()..]);
    }
    if lower.starts_with("system32\\") || lower.starts_with("syswow64\\") {
        return format!("C:\\Windows\\{p}");
    }
    p.to_string()
}

/// Windows FILETIME (100 ns ticks since 1601) to Unix milliseconds.
pub fn filetime_to_unix_millis(filetime: u64) -> Option<i64> {
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    if filetime < EPOCH_DIFF_100NS {
        return None;
    }
    Some(((filetime - EPOCH_DIFF_100NS) / 10_000) as i64)
}

/// The CapabilityAccessManager stores a program path with `#` for `\`.
pub fn consent_store_path(key_name: &str) -> String {
    key_name.replace('#', "\\")
}

/// One redirect from the hosts file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsEntry {
    pub address: String,
    pub host: String,
}

/// Parse the hosts file, keeping only entries that send a name somewhere.
/// Entries to loopback or 0.0.0.0 are blocks (as ad blockers write) and are
/// kept too, but flagged separately by [`sensitive_redirects`].
pub fn parse_hosts(text: &str) -> Vec<HostsEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let Some(address) = parts.next() else { continue };
        for host in parts {
            let host = host.to_lowercase();
            if host == "localhost" || host == "localhost.localdomain" {
                continue;
            }
            out.push(HostsEntry { address: address.to_string(), host });
        }
    }
    out
}

pub fn is_block_address(address: &str) -> bool {
    matches!(address, "0.0.0.0" | "127.0.0.1" | "::1" | "::" | "0:0:0:0:0:0:0:0")
}

/// Domains whose redirection is a red flag: banks and payment services,
/// big email providers, and security / update sites (redirecting those is how
/// malware stops antivirus from updating).
const SENSITIVE_DOMAINS: &[&str] = &[
    "microsoft.com", "windowsupdate.com", "update.microsoft.com", "live.com", "outlook.com",
    "office.com", "microsoftonline.com", "google.com", "gmail.com", "accounts.google.com",
    "apple.com", "icloud.com", "yahoo.com", "facebook.com", "whatsapp.com", "instagram.com",
    "paypal.com", "stripe.com", "visa.com", "mastercard.com", "americanexpress.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "hsbc.com", "barclays.co.uk",
    "lloydsbank.com", "natwest.com", "santander.com", "revolut.com", "monzo.com",
    "ecobank.com", "gtbank.com", "accessbankplc.com", "zenithbank.com", "firstbanknigeria.com",
    "stanbicbank.com", "standardbank.co.za", "absa.co.za", "fnb.co.za", "mtn.com",
    "safaricom.co.ke", "mpesa.com", "virustotal.com", "malwarebytes.com", "kaspersky.com",
    "avast.com", "avg.com", "eset.com", "bitdefender.com", "norton.com", "mcafee.com",
    "sophos.com", "trendmicro.com", "avira.com",
];

fn is_sensitive_host(host: &str) -> bool {
    SENSITIVE_DOMAINS
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
        || host.contains("bank")
}

/// Hosts entries that send a sensitive domain somewhere other than a block
/// address. Blocking `virustotal.com` to 0.0.0.0 still stops updates, so a
/// block of a security site counts too.
pub fn sensitive_redirects(entries: &[HostsEntry]) -> Vec<HostsEntry> {
    entries
        .iter()
        .filter(|e| {
            is_sensitive_host(&e.host)
                && (!is_block_address(&e.address) || is_security_host(&e.host))
        })
        .cloned()
        .collect()
}

fn is_security_host(host: &str) -> bool {
    [
        "windowsupdate.com", "update.microsoft.com", "virustotal.com", "malwarebytes.com",
        "kaspersky.com", "avast.com", "avg.com", "eset.com", "bitdefender.com", "norton.com",
        "mcafee.com", "sophos.com", "trendmicro.com", "avira.com",
    ]
    .iter()
    .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

/// Well-known public resolvers. A DNS server that is neither one of these nor
/// on the local network is worth a look.
const PUBLIC_RESOLVERS: &[&str] = &[
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "9.9.9.11", "149.112.112.11",
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
    "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0", "185.228.168.9", "185.228.169.9",
    "4.2.2.1", "4.2.2.2", "64.6.64.6", "64.6.65.6", "77.88.8.8", "77.88.8.1",
];

/// True if the resolver is on the local network or a well-known public one.
pub fn is_expected_dns(server: &str) -> bool {
    if PUBLIC_RESOLVERS.contains(&server) {
        return true;
    }
    if server.contains(':') {
        // IPv6: link-local, unique-local, loopback, or a public resolver's v6.
        let s = server.to_lowercase();
        return s.starts_with("fe80")
            || s.starts_with("fc")
            || s.starts_with("fd")
            || s == "::1"
            || s.starts_with("fec0")
            || s.starts_with("2606:4700:4700")
            || s.starts_with("2001:4860:4860")
            || s.starts_with("2620:fe:")
            || s.starts_with("2620:119:");
    }
    match server.parse::<Ipv4Addr>() {
        Ok(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                // Carrier-grade NAT, used by mobile hotspots and Tailscale.
                || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
        }
        Err(_) => false,
    }
}

/// True if a proxy server string points off this machine.
pub fn is_remote_proxy(server: &str) -> bool {
    // "host:port" or "http=host:port;https=host:port".
    server
        .split(';')
        .map(|part| part.rsplit('=').next().unwrap_or(part).trim())
        .filter(|p| !p.is_empty())
        .any(|p| {
            let host = p
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches("socks=")
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(p)
                .trim_matches(['[', ']']);
            !matches!(host.to_lowercase().as_str(), "localhost" | "127.0.0.1" | "::1" | "<local>")
        })
}

/// Map a PowerShell `Get-AuthenticodeSignature` status to the fact value.
pub fn signature_fact(status: &str) -> &'static str {
    match status {
        "Valid" => "signed",
        "NotSigned" => "unsigned",
        "HashMismatch" | "NotTrusted" => "invalid",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn normalises_names() {
        assert_eq!(normalise("Any Desk_Service"), "anydeskservice");
        assert_eq!(file_stem_normalised("C:\\Program Files\\AnyDesk\\AnyDesk.exe"), "anydesk");
    }

    #[test]
    fn user_writable_paths() {
        assert!(is_user_writable_path("C:\\Users\\amy\\AppData\\Roaming\\x\\x.exe"));
        assert!(is_user_writable_path("c:\\programdata\\upd\\u.exe"));
        assert!(is_user_writable_path("\\??\\C:\\Users\\Public\\a.exe"));
        assert!(!is_user_writable_path("C:\\Program Files\\Zoom\\zoom.exe"));
        assert!(!is_user_writable_path("C:\\Windows\\System32\\svchost.exe"));
    }

    #[test]
    fn extracts_executables_from_commands() {
        let e = |c: &str| executable_from_command(c, &no_env).unwrap();
        assert_eq!(e("\"C:\\Program Files\\A B\\a.exe\" --min"), "C:\\Program Files\\A B\\a.exe");
        assert_eq!(e("C:\\Program Files\\A B\\a.exe --min"), "C:\\Program Files\\A B\\a.exe");
        assert_eq!(e("C:\\x\\b.exe"), "C:\\x\\b.exe");
        assert_eq!(
            e("C:\\Windows\\System32\\rundll32.exe \"C:\\Users\\a\\x y.dll\",Start"),
            "C:\\Users\\a\\x y.dll"
        );
        assert_eq!(e("rundll32.exe C:\\u\\evil.dll,Run"), "C:\\u\\evil.dll");
        assert_eq!(e("\\??\\C:\\Windows\\x.sys"), "C:\\Windows\\x.sys");
        assert_eq!(e("\\SystemRoot\\System32\\drivers\\a.sys"), "C:\\Windows\\System32\\drivers\\a.sys");
        assert_eq!(e("system32\\svc.exe -k"), "C:\\Windows\\system32\\svc.exe");
        assert!(executable_from_command("   ", &no_env).is_none());
    }

    #[test]
    fn expands_environment_variables_via_the_callback() {
        let expand = |s: &str| s.replace("%APPDATA%", "C:\\Users\\a\\AppData\\Roaming");
        assert_eq!(
            executable_from_command("%APPDATA%\\upd\\upd.exe /s", &expand).unwrap(),
            "C:\\Users\\a\\AppData\\Roaming\\upd\\upd.exe"
        );
    }

    #[test]
    fn converts_filetime() {
        // 2021-01-01T00:00:00Z
        assert_eq!(filetime_to_unix_millis(132_539_328_000_000_000), Some(1_609_459_200_000));
        assert_eq!(filetime_to_unix_millis(0), None);
    }

    #[test]
    fn decodes_consent_store_paths() {
        assert_eq!(
            consent_store_path("C:#Program Files#Zoom#bin#Zoom.exe"),
            "C:\\Program Files\\Zoom\\bin\\Zoom.exe"
        );
    }

    #[test]
    fn parses_hosts_and_spots_sensitive_redirects() {
        let text = "# comment\n127.0.0.1 localhost\n0.0.0.0 ads.example.com tracker.example.com\n\
                    10.0.0.5 www.chase.com # fake bank\n0.0.0.0 update.microsoft.com\n\
                    1.2.3.4 myserver.lan\n";
        let entries = parse_hosts(text);
        assert_eq!(entries.len(), 5);
        let sensitive = sensitive_redirects(&entries);
        let hosts: Vec<&str> = sensitive.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, vec!["www.chase.com", "update.microsoft.com"]);
    }

    #[test]
    fn classifies_dns_servers() {
        assert!(is_expected_dns("192.168.1.1"));
        assert!(is_expected_dns("1.1.1.1"));
        assert!(is_expected_dns("100.100.100.100"));
        assert!(is_expected_dns("fe80::1"));
        assert!(!is_expected_dns("45.33.1.9"));
    }

    #[test]
    fn classifies_proxies() {
        assert!(!is_remote_proxy("127.0.0.1:8888"));
        assert!(!is_remote_proxy("localhost:3128"));
        assert!(is_remote_proxy("203.0.113.7:8080"));
        assert!(is_remote_proxy("http=127.0.0.1:80;https=evil.example:443"));
    }
}
