//! What this PC talked to, matched against stalkerware servers and the
//! websites that sell stalkerware (the Echap indicator set in the signed
//! bundle): the DNS client cache, open TCP connections and the hosts file.
//!
//! This is the check SpyGuard and TinyCheck do with a Raspberry Pi, read
//! from what Windows already records. It only sees recent activity: the DNS
//! cache holds names for minutes to hours, and connections only while they
//! are open, so finding nothing is not proof of nothing.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use psg_core::{keys, Indicator};

use crate::classify;
use crate::model::{Subject, SubjectKind};
use crate::raw::RawInventory;

/// Most evidence lines of one sort on a card; the rest are counted.
const MAX_LINES: usize = 10;

/// Programs whose connections mean a person browsing, not software running
/// unseen. WebView hosts (msedgewebview2) are apps, not browsers.
const BROWSERS: &[&str] = &[
    "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore", "waterfox", "librewolf",
    "chromium", "yandex", "arc",
];

/// What a host name is to a family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A server the spyware uploads to, or the buyer's dashboard.
    Server,
    /// A website that sells it.
    Sales,
}

/// Lookup tables over every stalkerware family in the bundle.
pub struct NetIndex<'a> {
    families: &'a [Indicator],
    servers: HashMap<&'a str, usize>,
    sales: HashMap<&'a str, usize>,
    ips: HashMap<IpAddr, usize>,
}

impl<'a> NetIndex<'a> {
    pub fn new(families: &'a [Indicator]) -> Self {
        let mut servers = HashMap::new();
        let mut sales = HashMap::new();
        let mut ips = HashMap::new();
        for (i, f) in families.iter().enumerate() {
            for d in &f.domains {
                servers.entry(d.as_str()).or_insert(i);
            }
            for w in &f.websites {
                sales.entry(w.as_str()).or_insert(i);
            }
            for a in &f.ips {
                if let Ok(ip) = a.parse::<IpAddr>() {
                    ips.entry(ip).or_insert(i);
                }
            }
        }
        Self { families, servers, sales, ips }
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.sales.is_empty() && self.ips.is_empty()
    }

    /// The family a host name belongs to: the listed name itself or any name
    /// under it. The most specific listed name wins, and where one name is
    /// both a server and a sales site it counts as a sales site, since a
    /// visit to the shop is the innocent reading.
    pub fn host(&self, name: &str) -> Option<(usize, Role, &'a str)> {
        self.find(name, true)
    }

    /// The family whose servers a host name belongs to, even where the
    /// name is also the shop's. Used for programs other than browsers: a
    /// program talking to the vendor's own domain is the spyware itself.
    pub fn server(&self, name: &str) -> Option<(usize, &'a str)> {
        self.find(name, false).map(|(i, _, k)| (i, k))
    }

    fn find(&self, name: &str, with_sales: bool) -> Option<(usize, Role, &'a str)> {
        let name = normalise_host(name);
        let mut rest = name.as_str();
        loop {
            if with_sales {
                if let Some((k, &i)) = self.sales.get_key_value(rest) {
                    return Some((i, Role::Sales, k));
                }
            }
            if let Some((k, &i)) = self.servers.get_key_value(rest) {
                return Some((i, Role::Server, k));
            }
            rest = rest.split_once('.')?.1;
            if !rest.contains('.') {
                return None; // never match a bare top-level domain
            }
        }
    }

    pub fn address(&self, ip: &IpAddr) -> Option<usize> {
        self.ips.get(ip).copied()
    }
}

fn normalise_host(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

/// Loopback, private, link-local and similar addresses never belong to a
/// stalkerware server and are skipped.
fn is_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]) // carrier-grade NAT
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local(&IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback() || v6.is_unspecified() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}

/// An IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) compares as its IPv4 form.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

#[derive(Default)]
struct Hits {
    lookups: BTreeSet<String>,
    sales: BTreeSet<String>,
    program_connections: BTreeSet<String>,
    browser_connections: BTreeSet<String>,
    address_only: BTreeSet<String>,
    hosts: BTreeSet<String>,
}

impl Hits {
    fn server_contact(&self) -> bool {
        !self.lookups.is_empty() || !self.program_connections.is_empty() || !self.browser_connections.is_empty()
    }
}

fn process_label(raw: &RawInventory, pid: u32) -> (String, bool) {
    match raw.processes.iter().find(|p| p.pid == pid) {
        Some(p) => {
            let stem = classify::file_stem_normalised(if p.path.is_empty() { &p.name } else { &p.path });
            let label = if p.path.is_empty() { format!("{} (process {pid})", p.name) } else { p.path.clone() };
            (label, BROWSERS.contains(&stem.as_str()))
        }
        None => (format!("process {pid}"), false),
    }
}

/// One subject per stalkerware family this PC had contact with.
pub fn subjects(raw: &RawInventory, families: &[Indicator]) -> Vec<Subject> {
    let index = NetIndex::new(families);
    if index.is_empty() {
        return Vec::new();
    }
    let mut hits: BTreeMap<usize, Hits> = BTreeMap::new();

    // Names the hosts file sets are loaded into the DNS cache whether or not
    // anything looked them up, so a blocklist must not read as contact.
    let hosts = raw.settings.hosts_text.as_deref().map(classify::parse_hosts).unwrap_or_default();
    let hosts_names: BTreeSet<&str> = hosts.iter().map(|e| e.host.as_str()).collect();
    for e in &hosts {
        if classify::is_block_address(&e.address) {
            continue;
        }
        if let Some((i, Role::Server, listed)) = index.host(&e.host) {
            hits.entry(i).or_default().hosts.insert(format!("{} {} (listed: {listed})", e.address, e.host));
        }
    }

    // Address -> names it was looked up under, to name a connection's far end.
    let mut names_by_ip: BTreeMap<IpAddr, BTreeSet<String>> = BTreeMap::new();
    for r in raw.dns_cache.iter().flatten() {
        let name = normalise_host(&r.name);
        if name.is_empty() || hosts_names.contains(name.as_str()) {
            continue;
        }
        let mut names = vec![name.clone()];
        if r.record_type == 5 {
            names.push(normalise_host(&r.data)); // CNAME: the alias target counts too
        }
        if matches!(r.record_type, 1 | 28) {
            if let Ok(ip) = r.data.trim().parse::<IpAddr>() {
                names_by_ip.entry(canonical(ip)).or_default().insert(name.clone());
            }
        }
        for n in names {
            match index.host(&n) {
                Some((i, Role::Server, listed)) => {
                    hits.entry(i).or_default().lookups.insert(if n == listed { n } else { format!("{n} (under {listed})") });
                }
                Some((i, Role::Sales, _)) => {
                    hits.entry(i).or_default().sales.insert(n);
                }
                None => {}
            }
        }
    }

    for c in raw.connections.iter().flatten() {
        let Ok(ip) = c.remote_address.trim().parse::<IpAddr>().map(canonical) else { continue };
        if is_local(&ip) {
            continue;
        }
        let (who, browser) = process_label(raw, c.pid);
        let mut named = false;
        for name in names_by_ip.get(&ip).into_iter().flatten() {
            let found = match index.server(name) {
                Some((i, _)) if !browser => Some((i, Role::Server)),
                _ => index.host(name).map(|(i, role, _)| (i, role)),
            };
            let Some((i, role)) = found else { continue };
            named = true;
            let line = format!("{who} → {name} ({ip}:{})", c.remote_port);
            let h = hits.entry(i).or_default();
            match (role, browser) {
                (Role::Sales, _) => h.sales.insert(line),
                (Role::Server, true) => h.browser_connections.insert(line),
                (Role::Server, false) => h.program_connections.insert(line),
            };
        }
        if !named {
            if let Some(i) = index.address(&ip) {
                hits.entry(i).or_default().address_only.insert(format!("{who} → {ip}:{}", c.remote_port));
            }
        }
    }

    hits.into_iter().map(|(i, h)| subject(&index.families[i], &h)).collect()
}

fn subject(family: &Indicator, h: &Hits) -> Subject {
    let title = if h.server_contact() || !h.address_only.is_empty() {
        format!("Contact with {} stalkerware servers", family.name)
    } else if !h.hosts.is_empty() {
        format!("Hosts file entry for {} stalkerware", family.name)
    } else {
        format!("Visit to a website selling {}", family.name)
    };
    let first = h
        .program_connections
        .iter()
        .chain(&h.browser_connections)
        .chain(&h.lookups)
        .chain(&h.address_only)
        .chain(&h.hosts)
        .chain(&h.sales)
        .next()
        .cloned()
        .unwrap_or_default();
    let mut s = Subject::new(format!("network:{}", family.id), SubjectKind::Network, title).detail(first);
    let f = &mut s.facts;
    f.set_text(keys::NAME, family.name.clone());
    f.set_text(keys::MATCHED_INDICATOR, family.id.clone());
    f.set_bool(keys::NET_SERVER_LOOKUP, !h.lookups.is_empty());
    f.set_bool(keys::NET_PROGRAM_CONNECTION, !h.program_connections.is_empty());
    f.set_bool(keys::NET_BROWSER_CONNECTION, !h.browser_connections.is_empty());
    f.set_bool(keys::NET_ADDRESS_ONLY, !h.address_only.is_empty());
    f.set_bool(keys::NET_SALES_SITE, !h.sales.is_empty());
    f.set_bool(keys::NET_HOSTS_ENTRY, !h.hosts.is_empty());

    for (label, lines) in [
        ("connection", &h.program_connections),
        ("connection (browser)", &h.browser_connections),
        ("looked up", &h.lookups),
        ("connection to a listed address", &h.address_only),
        ("hosts file", &h.hosts),
        ("sales website", &h.sales),
    ] {
        for (n, line) in lines.iter().take(MAX_LINES).enumerate() {
            s.evidence.insert(format!("{label} {:02}", n + 1), line.clone());
        }
        if lines.len() > MAX_LINES {
            s.evidence.insert(format!("{label} (more)"), format!("{} more", lines.len() - MAX_LINES));
        }
    }
    s.evidence.insert(
        "source".into(),
        format!("{} in the Echap stalkerware indicators (CC BY 4.0)", family.name),
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{DnsRecord, NetConnection, ProcessInfo};
    use psg_core::FactValue;

    fn family(id: &str, domains: &[&str], websites: &[&str], ips: &[&str]) -> Indicator {
        Indicator {
            id: id.into(),
            name: id.trim_start_matches("SW-").into(),
            domains: domains.iter().map(|s| s.to_string()).collect(),
            websites: websites.iter().map(|s| s.to_string()).collect(),
            ips: ips.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn families() -> Vec<Indicator> {
        vec![
            family("SW-Acme", &["panel.acmespy.com", "acmespy.com", "acme-7f3.firebaseio.com"], &["acmespy.com"], &["203.0.113.9"]),
            family("SW-Other", &["upload.otherspy.net"], &[], &[]),
        ]
    }

    fn dns(name: &str, data: &str, t: u16) -> DnsRecord {
        DnsRecord { name: name.into(), data: data.into(), record_type: t }
    }

    fn fact(s: &Subject, k: &str) -> bool {
        matches!(s.facts.get(k), Some(FactValue::Bool(true)))
    }

    #[test]
    fn host_matching_is_by_listed_name_and_below() {
        let fams = families();
        let ix = NetIndex::new(&fams);
        assert_eq!(ix.host("panel.acmespy.com"), Some((0, Role::Server, "panel.acmespy.com")));
        assert_eq!(ix.host("EU.Panel.AcmeSpy.com."), Some((0, Role::Server, "panel.acmespy.com")));
        assert_eq!(ix.host("www.acmespy.com"), Some((0, Role::Sales, "acmespy.com")), "shop beats server");
        assert_eq!(ix.host("acme-7f3.firebaseio.com"), Some((0, Role::Server, "acme-7f3.firebaseio.com")));
        assert_eq!(ix.host("other.firebaseio.com"), None, "a shared parent is never matched");
        assert_eq!(ix.host("firebaseio.com"), None);
        assert_eq!(ix.host("notacmespy.com"), None);
        assert_eq!(ix.host("com"), None);
    }

    #[test]
    fn a_program_connected_to_a_server_is_found_with_its_path() {
        let raw = RawInventory {
            processes: vec![ProcessInfo { name: "svc.exe".into(), path: "C:\\Users\\a\\AppData\\svc.exe".into(), pid: 77 }],
            dns_cache: Some(vec![dns("upload.otherspy.net", "198.51.100.4", 1)]),
            connections: Some(vec![NetConnection {
                remote_address: "::ffff:198.51.100.4".into(),
                remote_port: 443,
                state: "Established".into(),
                pid: 77,
            }]),
            ..Default::default()
        };
        let subs = subjects(&raw, &families());
        assert_eq!(subs.len(), 1);
        let s = &subs[0];
        assert_eq!(s.id, "network:SW-Other");
        assert_eq!(s.kind, SubjectKind::Network);
        assert!(fact(s, keys::NET_PROGRAM_CONNECTION));
        assert!(fact(s, keys::NET_SERVER_LOOKUP));
        assert!(!fact(s, keys::NET_BROWSER_CONNECTION));
        assert!(s.detail.contains("svc.exe") && s.detail.contains("upload.otherspy.net"), "{}", s.detail);
    }

    #[test]
    fn browser_visits_and_shop_visits_are_told_apart() {
        let raw = RawInventory {
            processes: vec![ProcessInfo { name: "msedge.exe".into(), path: "C:\\Program Files\\Edge\\msedge.exe".into(), pid: 5 }],
            dns_cache: Some(vec![dns("panel.acmespy.com", "203.0.113.20", 1), dns("www.acmespy.com", "203.0.113.21", 1)]),
            connections: Some(vec![
                NetConnection { remote_address: "203.0.113.20".into(), remote_port: 443, pid: 5, ..Default::default() },
                NetConnection { remote_address: "203.0.113.21".into(), remote_port: 443, pid: 5, ..Default::default() },
            ]),
            ..Default::default()
        };
        let s = &subjects(&raw, &families())[0];
        assert!(fact(s, keys::NET_BROWSER_CONNECTION));
        assert!(!fact(s, keys::NET_PROGRAM_CONNECTION));
        assert!(fact(s, keys::NET_SALES_SITE));
        assert!(s.title.starts_with("Contact with Acme"));
    }

    #[test]
    fn a_program_talking_to_the_shop_domain_is_the_spyware() {
        // acmespy.com is both the shop and a server. A browser there is
        // shopping; any other program there is the spyware uploading.
        let raw = RawInventory {
            processes: vec![
                ProcessInfo { name: "agent.exe".into(), path: "C:\\ProgramData\\agent.exe".into(), pid: 9 },
                ProcessInfo { name: "firefox.exe".into(), path: "C:\\Program Files\\Mozilla Firefox\\firefox.exe".into(), pid: 8 },
            ],
            dns_cache: Some(vec![dns("acmespy.com", "203.0.113.30", 1)]),
            connections: Some(vec![
                NetConnection { remote_address: "203.0.113.30".into(), remote_port: 443, pid: 9, ..Default::default() },
                NetConnection { remote_address: "203.0.113.30".into(), remote_port: 443, pid: 8, ..Default::default() },
            ]),
            ..Default::default()
        };
        let s = &subjects(&raw, &families())[0];
        assert!(fact(s, keys::NET_PROGRAM_CONNECTION));
        assert!(fact(s, keys::NET_SALES_SITE), "the browser visit is still the shop");
        assert!(!fact(s, keys::NET_BROWSER_CONNECTION));
    }

    #[test]
    fn a_shop_visit_alone_is_only_a_sales_site() {
        let raw = RawInventory { dns_cache: Some(vec![dns("acmespy.com", "203.0.113.21", 1)]), ..Default::default() };
        let s = &subjects(&raw, &families())[0];
        assert!(fact(s, keys::NET_SALES_SITE));
        assert!(!fact(s, keys::NET_SERVER_LOOKUP));
        assert_eq!(s.title, "Visit to a website selling Acme");
    }

    #[test]
    fn hosts_blocklists_are_not_contact_but_redirects_are_noted() {
        let raw = RawInventory {
            settings: crate::raw::SettingsRaw {
                hosts_text: Some("0.0.0.0 panel.acmespy.com\n203.0.113.50 upload.otherspy.net\n".into()),
                ..Default::default()
            },
            // Windows preloads hosts entries into the DNS cache.
            dns_cache: Some(vec![dns("panel.acmespy.com", "0.0.0.0", 1), dns("upload.otherspy.net", "203.0.113.50", 1)]),
            ..Default::default()
        };
        let subs = subjects(&raw, &families());
        assert_eq!(subs.len(), 1, "the block is the owner protecting themselves: {subs:?}");
        assert!(fact(&subs[0], keys::NET_HOSTS_ENTRY));
        assert!(!fact(&subs[0], keys::NET_SERVER_LOOKUP), "a preloaded hosts name is not a lookup");
    }

    #[test]
    fn listed_addresses_without_a_name_are_weak_and_local_ones_are_ignored() {
        let raw = RawInventory {
            connections: Some(vec![
                NetConnection { remote_address: "203.0.113.9".into(), remote_port: 80, pid: 1, ..Default::default() },
                NetConnection { remote_address: "192.168.1.1".into(), remote_port: 80, pid: 1, ..Default::default() },
            ]),
            ..Default::default()
        };
        let subs = subjects(&raw, &families());
        assert_eq!(subs.len(), 1);
        assert!(fact(&subs[0], keys::NET_ADDRESS_ONLY));
        assert!(!fact(&subs[0], keys::NET_PROGRAM_CONNECTION));
    }

    #[test]
    fn cname_targets_count_and_nothing_read_means_no_subjects() {
        let raw = RawInventory {
            dns_cache: Some(vec![dns("innocent-alias.example", "acme-7f3.firebaseio.com", 5)]),
            ..Default::default()
        };
        assert!(fact(&subjects(&raw, &families())[0], keys::NET_SERVER_LOOKUP));
        assert!(subjects(&RawInventory::default(), &families()).is_empty());
        assert!(subjects(&raw, &[]).is_empty());
    }

    #[test]
    fn local_addresses() {
        for a in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1"] {
            assert!(is_local(&a.parse().unwrap()), "{a}");
        }
        for a in ["203.0.113.9", "8.8.8.8", "2001:db8::1", "100.128.0.1"] {
            assert!(!is_local(&a.parse().unwrap()), "{a}");
        }
    }
}
