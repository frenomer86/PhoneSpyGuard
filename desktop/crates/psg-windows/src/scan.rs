//! Turning a raw inventory into scored findings.
//!
//! [`build_subjects`] is the judgement-free step: it maps what was read into
//! subjects and facts, folds every sighting of a known product into one card,
//! and marks what is new since the baseline. [`score`] then runs the shared
//! detection engine over them. Both are pure and run on any platform.

use std::collections::{BTreeMap, BTreeSet};

use psg_core::{keys, Confidence, DetectionEngine, Facts, Indicator, RuleBundle, Severity};

use crate::classify::{self, is_user_writable_path};
use crate::indicators::{match_indicator, service_matches, MatchReason};
use crate::model::{Finding, Report, Subject, SubjectKind};
use crate::raw::RawInventory;
use crate::watch::Baseline;

/// Owner answers and history that change how a subject is read.
#[derive(Debug, Clone)]
pub struct Context<'a> {
    /// The previous check's baseline; None on the very first check.
    pub baseline: Option<&'a Baseline>,
    /// Subject id -> the fingerprint it had when the owner said they set
    /// it up. The answer counts only while the fingerprint still matches.
    pub owner_trusted: &'a BTreeMap<String, String>,
}

fn sig_of<'a>(raw: &'a RawInventory, path: &str) -> (&'a str, &'a str) {
    raw.signatures
        .get(&path.to_lowercase())
        .map(|s| (s.status.as_str(), s.signer.as_str()))
        .unwrap_or(("unknown", ""))
}

fn add_file_facts(facts: &mut Facts, raw: &RawInventory, path: &str) {
    if path.is_empty() {
        return;
    }
    let (status, signer) = sig_of(raw, path);
    facts.set_text(keys::PATH, path);
    facts.set_text(keys::SIGNATURE, status);
    if !signer.is_empty() {
        facts.set_text(keys::SIGNER, signer);
    }
    facts.set_bool(keys::USER_WRITABLE_PATH, is_user_writable_path(path));
    if let Some(h) = raw.hashes.get(&path.to_lowercase()) {
        facts.set_text(keys::SHA256, h.clone());
    }
}

/// Build every subject from the inventory.
pub fn build_subjects(raw: &RawInventory, bundle: &RuleBundle, ctx: &Context<'_>) -> Vec<Subject> {
    let mut subjects = Vec::new();
    subjects.extend(products(raw, bundle));
    subjects.extend(autostarts(raw));
    subjects.extend(processes(raw));
    subjects.extend(extensions(raw));
    subjects.extend(settings(raw));
    subjects.extend(camera_mic(raw));
    subjects.extend(programs(raw));
    subjects.extend(crate::network::subjects(raw, &bundle.indicators.stalkerware));
    subjects.extend(stalkerware_files(raw, bundle));

    for s in &mut subjects {
        if let Some(baseline) = ctx.baseline {
            // Volatile kinds and camera use don't get "new" flags, nor do
            // things the baseline's collectors never read.
            if !s.kind.is_volatile() && s.kind != SubjectKind::CameraMic && baseline.covers(s) {
                s.facts.set_bool(keys::NEW_SINCE_BASELINE, !baseline.contains(&s.id));
            }
        }
        s.fingerprint = crate::watch::fingerprint(s);
        match ctx.owner_trusted.get(&s.id) {
            Some(fp) if *fp == s.fingerprint => s.facts.set_bool(keys::OWNER_TRUSTED, true),
            Some(_) => {
                s.facts.set_bool(keys::OWNER_TRUST_STALE, true);
                s.evidence.insert(
                    "your earlier answer".into(),
                    "You said you set this up, but it has changed since, so that answer no longer counts.".into(),
                );
            }
            None => {}
        }
    }
    subjects
}

// --- known products ---------------------------------------------------------

struct Sighting {
    how: String,
    path: String,
    reason: MatchReason,
}

fn products(raw: &RawInventory, bundle: &RuleBundle) -> Vec<Subject> {
    let mut out = Vec::new();
    #[derive(PartialEq, Clone, Copy)]
    enum List {
        Monitoring,
        RemoteAccess,
        Oversight,
    }
    let lists: [(&[Indicator], List); 3] = [
        (&bundle.indicators.monitoring, List::Monitoring),
        (&bundle.indicators.remote_access, List::RemoteAccess),
        (&bundle.indicators.oversight, List::Oversight),
    ];
    for (list, kind) in lists {
        for ind in list {
            let sightings = sightings(raw, ind);
            if sightings.is_empty() {
                continue;
            }
            let unattended = kind == List::RemoteAccess
                && raw.services.iter().any(|s| s.start != 4 && service_matches(ind, &s.name));
            let running = sightings.iter().any(|s| s.how.starts_with("running"));
            let path = sightings.iter().map(|s| s.path.as_str()).find(|p| !p.is_empty()).unwrap_or("");

            let mut subject = Subject::new(format!("product:{}", ind.id), SubjectKind::Product, ind.name.clone())
                .detail(if path.is_empty() { sightings[0].how.clone() } else { path.to_string() });
            let f = &mut subject.facts;
            f.set_text(keys::NAME, ind.name.clone());
            f.set_text(keys::MATCHED_INDICATOR, ind.id.clone());
            match kind {
                List::Monitoring => f.set_bool(keys::KNOWN_MONITORING_MATCH, true),
                List::RemoteAccess => {
                    f.set_bool(keys::REMOTE_ACCESS_TOOL, true);
                    f.set_bool(keys::UNATTENDED_ACCESS, unattended);
                }
                List::Oversight => f.set_bool(keys::OVERSIGHT_TOOL, true),
            }
            f.set_bool(keys::RUNNING, running);
            add_file_facts(f, raw, path);
            for (i, s) in sightings.iter().enumerate() {
                let line = if s.path.is_empty() { s.reason.describe() } else { format!("{} ({})", s.path, s.reason.describe()) };
                subject.evidence.insert(format!("seen {:02}: {}", i + 1, s.how), line);
            }
            if unattended {
                let svcs: Vec<&str> = raw
                    .services
                    .iter()
                    .filter(|s| s.start != 4 && service_matches(ind, &s.name))
                    .map(|s| s.name.as_str())
                    .collect();
                subject.evidence.insert("unattended service".into(), svcs.join(", "));
            }
            out.push(subject);
        }
    }
    out
}

fn sightings(raw: &RawInventory, ind: &Indicator) -> Vec<Sighting> {
    let mut out = Vec::new();
    let hash = |p: &str| raw.hashes.get(&p.to_lowercase()).map(String::as_str);
    for p in &raw.installed {
        if let Some(reason) = match_indicator(ind, &[&p.name], &p.publisher, None) {
            out.push(Sighting { how: "installed program".into(), path: p.install_location.clone(), reason });
        }
    }
    for p in &raw.processes {
        let stem = file_name(&p.path, &p.name);
        let (_, signer) = sig_of(raw, &p.path);
        if let Some(reason) = match_indicator(ind, &[&stem], signer, hash(&p.path)) {
            out.push(Sighting { how: format!("running process {}", p.name), path: p.path.clone(), reason });
        }
    }
    for s in &raw.services {
        let stem = file_name(&s.path, "");
        let (_, signer) = sig_of(raw, &s.path);
        if let Some(reason) = match_indicator(ind, &[&s.name, &s.display_name, &stem], signer, hash(&s.path)) {
            out.push(Sighting { how: format!("service {}", s.name), path: s.path.clone(), reason });
        }
    }
    for a in &raw.autostarts {
        if a.location == "service" {
            continue; // already seen as a service
        }
        let stem = file_name(&a.path, "");
        let (_, signer) = sig_of(raw, &a.path);
        if let Some(reason) = match_indicator(ind, &[&a.name, &stem], signer, hash(&a.path)) {
            out.push(Sighting { how: format!("starts automatically ({})", a.location), path: a.path.clone(), reason });
        }
    }
    out
}

fn file_name(path: &str, fallback: &str) -> String {
    let f = path.rsplit(['\\', '/']).next().unwrap_or("");
    let f = if f.is_empty() { fallback } else { f };
    f.rsplit_once('.').map(|(s, _)| s).unwrap_or(f).to_string()
}

// --- autostart (FR-DSK-03) ----------------------------------------------------

/// Places that load code into Windows itself or into every program, as
/// Autoruns lists them. Anything there not signed by Microsoft is unusual.
pub const DEEP_LOCATIONS: &[&str] = &[
    "appinit", "appcert", "lsa", "winlogon_notify", "boot_execute", "silent_exit", "cmd_autorun",
    "com_hijack", "print_monitor", "netsh", "shell_extension", "bho", "active_setup", "terminal_server",
];

fn is_microsoft_signed(raw: &RawInventory, path: &str) -> bool {
    let (status, signer) = sig_of(raw, path);
    status == "signed" && signer.to_lowercase().starts_with("microsoft ")
}

fn autostarts(raw: &RawInventory) -> Vec<Subject> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |location: &str, place: &str, name: &str, command: &str, path: &str, since: u32| {
        let id = format!("autostart:{location}:{}:{}", name.to_lowercase(), path.to_lowercase());
        if !seen.insert(id.clone()) {
            return;
        }
        let title = if name.is_empty() { file_name(path, "(unnamed)") } else { name.to_string() };
        let mut s = Subject::new(id, SubjectKind::Autostart, title)
            .detail(if path.is_empty() { command.to_string() } else { path.to_string() })
            .evidence("where", place)
            .evidence("command", command);
        s.facts.set_text(keys::AUTOSTART_LOCATION, location);
        s.facts.set_text(keys::NAME, name);
        add_file_facts(&mut s.facts, raw, path);
        if location == "wmi" {
            s.facts.set_bool(keys::WMI_SUBSCRIPTION, true);
        }
        // Only here, so adding the fact doesn't change the fingerprint of
        // every older autostart the owner already vouched for.
        if DEEP_LOCATIONS.contains(&location) {
            s.facts.set_bool(keys::MICROSOFT_SIGNED, is_microsoft_signed(raw, path));
        }
        s.since_coverage = since;
        out.push(s);
    };
    for a in &raw.autostarts {
        push(&a.location, &a.place, &a.name, &a.command, &a.path, a.since_coverage);
    }
    for svc in raw.services.iter().filter(|s| s.start == 2 && !s.driver) {
        let place = format!("Service {} ({})", svc.name, svc.display_name);
        push("service", &place, &svc.name, &svc.path, &svc.path, 0);
    }
    out
}

// --- stalkerware installer files ------------------------------------------------

/// Android app files in the owner's folders whose hash is a known stalkerware
/// sample. On a PC that means someone downloaded spyware to put on a phone.
fn stalkerware_files(raw: &RawInventory, bundle: &RuleBundle) -> Vec<Subject> {
    let by_hash: BTreeMap<&str, &Indicator> = bundle
        .indicators
        .stalkerware
        .iter()
        .flat_map(|f| f.sha256.iter().map(move |h| (h.as_str(), f)))
        .collect();
    raw.apk_files
        .iter()
        .filter_map(|file| {
            let family = by_hash.get(file.sha256.to_lowercase().as_str())?;
            let mut s = Subject::new(
                format!("file:{}", file.path.to_lowercase()),
                SubjectKind::File,
                format!("{} stalkerware installer", family.name),
            )
            .detail(file.path.clone())
            .evidence("file hash (SHA-256)", file.sha256.to_lowercase())
            .evidence("size", format!("{} bytes", file.size))
            .evidence("source", format!("{} sample in the Echap stalkerware indicators (CC BY 4.0)", family.name));
            if let Some(t) = file.modified_millis {
                s.evidence.insert("last changed (ms since 1970)".into(), t.to_string());
            }
            let f = &mut s.facts;
            f.set_text(keys::NAME, family.name.clone());
            f.set_text(keys::MATCHED_INDICATOR, family.id.clone());
            f.set_bool(keys::STALKERWARE_FILE, true);
            f.set_text(keys::PATH, file.path.clone());
            f.set_text(keys::SHA256, file.sha256.to_lowercase());
            f.set_bool(keys::USER_WRITABLE_PATH, is_user_writable_path(&file.path));
            s.since_coverage = 1;
            Some(s)
        })
        .collect()
}

// --- processes ----------------------------------------------------------------

fn processes(raw: &RawInventory) -> Vec<Subject> {
    let installed_roots: Vec<String> = raw
        .installed
        .iter()
        .map(|p| p.install_location.trim_end_matches('\\').to_lowercase())
        .filter(|p| p.len() > 3)
        .collect();
    let mut seen = BTreeSet::new();
    raw.processes
        .iter()
        .filter(|p| !p.path.is_empty())
        .filter(|p| {
            let lower = p.path.to_lowercase();
            !lower.starts_with("c:\\windows\\")
                && !installed_roots.iter().any(|root| lower.starts_with(&format!("{root}\\")))
        })
        .filter(|p| seen.insert(p.path.to_lowercase()))
        .map(|p| {
            let mut s = Subject::new(format!("process:{}", p.path.to_lowercase()), SubjectKind::Process, p.name.clone())
                .detail(p.path.clone());
            s.facts.set_text(keys::NAME, p.name.clone());
            s.facts.set_bool(keys::RUNNING, true);
            add_file_facts(&mut s.facts, raw, &p.path);
            s
        })
        .collect()
}

// --- installed programs (inventory) ---------------------------------------------

fn programs(raw: &RawInventory) -> Vec<Subject> {
    let mut seen = BTreeSet::new();
    raw.installed
        .iter()
        .filter(|p| seen.insert(classify::normalise(&p.name)))
        .map(|p| {
            let mut s = Subject::new(
                format!("program:{}", classify::normalise(&p.name)),
                SubjectKind::Program,
                p.name.clone(),
            )
            .detail(p.publisher.clone())
            .evidence("version", p.version.clone())
            .evidence("folder", p.install_location.clone())
            .evidence("installed", p.install_date.clone());
            s.facts.set_text(keys::NAME, p.name.clone());
            s.facts.set_text(keys::PUBLISHER, p.publisher.clone());
            s
        })
        .collect()
}

// --- browser extensions (FR-DSK-05) -------------------------------------------

fn extensions(raw: &RawInventory) -> Vec<Subject> {
    raw.extensions
        .iter()
        .map(|e| {
            let mut s = Subject::new(
                format!("ext:{}:{}:{}", e.browser.to_lowercase(), e.profile.to_lowercase(), e.id),
                SubjectKind::Extension,
                e.name.clone(),
            )
            .detail(format!("{} · profile {} · {}", e.browser, e.profile, if e.enabled { "on" } else { "off" }))
            .evidence("extension id", e.id.clone())
            .evidence("version", e.version.clone())
            .evidence("permissions", e.permissions.join(", "));
            let f = &mut s.facts;
            f.set_text(keys::NAME, e.name.clone());
            f.set_text(keys::BROWSER, e.browser.clone());
            f.set_bool(keys::EXT_ALL_SITES, e.all_sites);
            f.set_bool(keys::EXT_OUTSIDE_STORE, e.outside_store);
            f.set_bool(keys::EXT_FORCE_INSTALLED, e.force_installed);
            f.set_text_list(keys::EXT_PERMISSIONS, e.permissions.clone());
            s
        })
        .collect()
}

// --- user accounts (FR-DSK-01) ---------------------------------------------------

/// Accounts someone could use to get into this PC without the owner seeing:
/// enabled accounts hidden from the sign-in screen, the built-in Administrator
/// or Guest turned on, and automatic sign-in.
fn accounts_subject(
    st: &crate::raw::SettingsRaw,
    accounts: &[crate::raw::LocalAccount],
    setting: &dyn Fn(&str, &str, String) -> Subject,
) -> Subject {
    let enabled: Vec<_> = accounts.iter().filter(|a| a.enabled).collect();
    // Windows' own service accounts (DefaultAccount, WDAGUtilityAccount) are
    // hidden by design; Administrator and Guest are reported on their own.
    let hidden: Vec<_> = enabled
        .iter()
        .filter(|a| !matches!(a.rid(), Some(500 | 501 | 503 | 504)))
        .filter(|a| st.hidden_from_sign_in.iter().any(|h| h.eq_ignore_ascii_case(&a.name)))
        .collect();
    let builtin_admin = enabled.iter().any(|a| a.rid() == Some(500));
    let guest = enabled.iter().any(|a| a.rid() == Some(501));
    let mut s = setting(
        "accounts",
        "User accounts",
        format!(
            "{} enabled: {}",
            enabled.len(),
            enabled.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", ")
        ),
    );
    s.facts.set_number(keys::HIDDEN_ACCOUNTS, hidden.len() as i64);
    s.facts.set_bool(keys::BUILTIN_ADMIN_ENABLED, builtin_admin);
    s.facts.set_bool(keys::GUEST_ENABLED, guest);
    s.facts.set_bool(keys::AUTO_LOGON, st.auto_logon_user.is_some());
    s.facts.set_bool(keys::AUTO_LOGON_PASSWORD_STORED, st.auto_logon_password_stored);
    // Fingerprinted, so the watch reports an account that appears or is enabled.
    s.facts.set_text_list(
        "pc.enabled_account_sids",
        enabled.iter().map(|a| a.sid.clone()).collect(),
    );
    for a in &hidden {
        s.evidence.insert(format!("hidden account {}", a.name), a.sid.clone());
    }
    if builtin_admin {
        s.evidence.insert("built-in Administrator".into(), "enabled".into());
    }
    if guest {
        s.evidence.insert("Guest account".into(), "enabled".into());
    }
    if let Some(user) = &st.auto_logon_user {
        let how = if st.auto_logon_password_stored { "password stored in the registry" } else { "on" };
        s.evidence.insert(format!("automatic sign-in as {user}"), how.into());
    }
    s
}

// --- interception and control settings (FR-DSK-06) ------------------------------

fn settings(raw: &RawInventory) -> Vec<Subject> {
    let st = &raw.settings;
    let managed = st.part_of_domain || st.mdm_enrolled;
    let mut out = Vec::new();
    let setting = |id: &str, title: &str, detail: String| {
        let mut s = Subject::new(format!("setting:{id}"), SubjectKind::Setting, title).detail(detail);
        s.facts.set_text(keys::SETTING, id);
        if managed {
            s.facts.set_bool(keys::MANAGED_BY_EMPLOYER, true);
        }
        s
    };

    // Certificates and proxy share one card: together they are interception.
    let proxy_remote = st.proxy_enabled && classify::is_remote_proxy(&st.proxy_server);
    let pac = !st.auto_config_url.trim().is_empty();
    let mut web = setting(
        "web_interception",
        "Web traffic interception",
        format!(
            "{} added root certificate(s); proxy {}",
            st.user_root_certs.len(),
            if proxy_remote { st.proxy_server.as_str() } else if pac { "script set" } else { "off" }
        ),
    );
    web.facts.set_bool(keys::ROOT_CERT_USER_ADDED, !st.user_root_certs.is_empty());
    web.facts.set_bool(keys::PROXY_ENABLED, st.proxy_enabled);
    web.facts.set_bool(keys::PROXY_REMOTE, proxy_remote);
    web.facts.set_bool(keys::PAC_URL_SET, pac);
    for c in &st.user_root_certs {
        web.evidence.insert(format!("root certificate {}", c.thumbprint), c.subject.clone());
    }
    if st.proxy_enabled {
        web.evidence.insert("proxy server".into(), st.proxy_server.clone());
    }
    if pac {
        web.evidence.insert("proxy script".into(), st.auto_config_url.clone());
    }
    web.evidence.insert(
        "machine root certificates".into(),
        format!("{} (new ones are reported by the change watch)", st.machine_root_thumbprints.len()),
    );
    // The machine store's exact contents are fingerprinted so the watch sees additions.
    web.facts.set_text_list("pc.machine_roots", st.machine_root_thumbprints.clone());
    out.push(web);

    if !st.dns_servers.is_empty() {
        let unusual: Vec<&String> = st.dns_servers.iter().filter(|d| !classify::is_expected_dns(d)).collect();
        let mut dns = setting("dns", "DNS servers", st.dns_servers.join(", "));
        dns.facts.set_bool(keys::DNS_UNUSUAL, !unusual.is_empty());
        dns.facts.set_text_list("pc.dns_servers", st.dns_servers.clone());
        if !unusual.is_empty() {
            dns.evidence.insert("unusual".into(), unusual.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
        }
        out.push(dns);
    }

    if let Some(text) = &st.hosts_text {
        let entries = classify::parse_hosts(text);
        let sensitive = classify::sensitive_redirects(&entries);
        // Entries to 0.0.0.0 / 127.0.0.1 are blocks, as ad blockers write; only
        // entries that send a name to some other address are redirects.
        let redirects = entries.iter().filter(|e| !classify::is_block_address(&e.address)).count();
        let mut hosts = setting(
            "hosts",
            "Hosts file",
            format!("{redirects} redirect(s), {} blocked name(s)", entries.len() - redirects),
        );
        hosts.facts.set_number(keys::HOSTS_REDIRECTS, redirects as i64);
        hosts.facts.set_bool(keys::HOSTS_REDIRECTS_SENSITIVE, !sensitive.is_empty());
        hosts.facts.set_text_list(
            "pc.hosts_entries",
            entries.iter().map(|e| format!("{} {}", e.address, e.host)).collect(),
        );
        for e in sensitive.iter().take(20) {
            hosts.evidence.insert(format!("sensitive {}", e.host), e.address.clone());
        }
        out.push(hosts);
    }

    if let Some(rdp) = st.rdp_enabled {
        let mut s = setting("rdp", "Remote Desktop", if rdp { "on".into() } else { "off".into() });
        s.facts.set_bool(keys::RDP_ENABLED, rdp);
        out.push(s);
    }

    if let Some(admins) = &st.admins {
        // Extra = admin user accounts other than the owner and the built-in
        // Administrator (RID 500), which Windows keeps disabled by default.
        let extra: Vec<&crate::raw::AdminAccount> = admins
            .iter()
            .filter(|a| a.object_class.eq_ignore_ascii_case("user"))
            .filter(|a| !a.is_current_user && !a.sid.ends_with("-500"))
            .collect();
        let mut s = setting(
            "admins",
            "Administrator accounts",
            admins.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", "),
        );
        s.facts.set_number(keys::EXTRA_ADMINS, extra.len() as i64);
        s.facts.set_text_list("pc.admin_sids", admins.iter().map(|a| a.sid.clone()).collect());
        for a in extra {
            s.evidence.insert(format!("other administrator {}", a.name), a.sid.clone());
        }
        out.push(s);
    }

    if let Some(accounts) = &st.accounts {
        out.push(accounts_subject(st, accounts, &setting));
    }

    let third_party_av: Vec<&String> = st
        .av_products
        .iter()
        .filter(|p| !p.to_lowercase().contains("defender"))
        .collect();
    let has_defender_data = st.defender_realtime_enabled.is_some()
        || st.defender_disabled_by_policy
        || st.defender_exclusions.is_some();
    if has_defender_data {
        let realtime_off = st.defender_realtime_enabled == Some(false) && third_party_av.is_empty();
        let mut s = setting(
            "defender",
            "Microsoft Defender",
            match (st.defender_realtime_enabled, third_party_av.first()) {
                (_, Some(av)) => format!("{av} is the active antivirus"),
                (Some(true), _) => "real-time protection on".into(),
                (Some(false), _) => "real-time protection OFF".into(),
                (None, _) => "status unknown".into(),
            },
        );
        s.facts.set_bool(keys::DEFENDER_REALTIME_OFF, realtime_off);
        s.facts.set_bool(keys::DEFENDER_DISABLED_BY_POLICY, st.defender_disabled_by_policy);
        if !third_party_av.is_empty() {
            s.facts.set_bool("pc.third_party_av", true);
            s.evidence.insert(
                "antivirus products".into(),
                st.av_products.join(", "),
            );
        }
        if let Some(ex) = &st.defender_exclusions {
            s.facts.set_number(keys::DEFENDER_EXCLUSIONS, ex.len() as i64);
            s.facts.set_text_list("pc.defender_exclusion_list", ex.clone());
            for (i, e) in ex.iter().enumerate().take(30) {
                s.evidence.insert(format!("exclusion {:02}", i + 1), e.clone());
            }
        }
        out.push(s);
    }
    out
}

// --- camera and microphone (FR-DSK-07) -----------------------------------------

fn camera_mic(raw: &RawInventory) -> Vec<Subject> {
    raw.camera_mic
        .iter()
        .map(|u| {
            let device = if u.device == "webcam" { "camera" } else { "microphone" };
            let app_name = if u.packaged { u.app.split('_').next().unwrap_or(&u.app).to_string() } else { file_name(&u.app, &u.app) };
            let mut s = Subject::new(
                format!("cammic:{}:{}", u.device, u.app.to_lowercase()),
                SubjectKind::CameraMic,
                format!("{app_name} used the {device}"),
            )
            .detail(u.app.clone());
            let f = &mut s.facts;
            f.set_text(keys::DEVICE, u.device.clone());
            f.set_bool(keys::PACKAGED_APP, u.packaged);
            if let Some(t) = u.last_start_millis {
                f.set_number(keys::LAST_USED_MILLIS, t);
            }
            let in_use = u.last_start_millis.is_some() && u.last_stop_millis.unwrap_or(0) == 0;
            f.set_bool(keys::IN_USE_NOW, in_use);
            if !u.packaged {
                add_file_facts(f, raw, &u.app);
            }
            s
        })
        .collect()
}

// --- scoring ------------------------------------------------------------------

/// Run the engine over every subject and build the report.
pub fn score(
    raw: &RawInventory,
    subjects: Vec<Subject>,
    engine: &DetectionEngine,
    started_millis: i64,
    finished_millis: i64,
) -> Report {
    let bundle = engine.bundle();
    let rules: BTreeMap<&str, &psg_core::Rule> = bundle.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let removal_by_indicator: BTreeMap<&str, &str> = bundle
        .indicators
        .monitoring
        .iter()
        .chain(&bundle.indicators.remote_access)
        .chain(&bundle.indicators.oversight)
        .chain(&bundle.indicators.stalkerware)
        .map(|i| (i.id.as_str(), i.removal.as_str()))
        .collect();

    // What was read but only matched, not scored one by one.
    let mut checked: BTreeMap<String, usize> = BTreeMap::new();
    if let Some(dns) = &raw.dns_cache {
        checked.insert("dns_name".into(), dns.iter().map(|r| r.name.to_lowercase()).collect::<BTreeSet<_>>().len());
    }
    if let Some(c) = &raw.connections {
        checked.insert("connection".into(), c.len());
    }
    checked.insert("apk_file".into(), raw.apk_files.len());
    let mut camera_mic: Vec<Subject> = Vec::new();
    let mut findings = Vec::new();
    for subject in subjects {
        *checked.entry(subject.kind.as_str().to_string()).or_default() += 1;
        if subject.kind == SubjectKind::CameraMic {
            camera_mic.push(subject.clone());
        }
        let evaluation = engine.evaluate(&subject.id, &subject.facts);
        let mut explain = Vec::new();
        let mut steps = Vec::new();
        for sig in &evaluation.verdict.signals {
            if let Some(rule) = rules.get(sig.rule_id.as_str()) {
                if !rule.explain.is_empty() && !explain.contains(&rule.explain) {
                    explain.push(rule.explain.clone());
                }
                for st in &rule.steps {
                    if !steps.contains(st) {
                        steps.push(st.clone());
                    }
                }
            }
        }
        let removal = match subject.facts.get(keys::MATCHED_INDICATOR) {
            Some(psg_core::FactValue::Text(id)) => {
                removal_by_indicator.get(id.as_str()).filter(|r| !r.is_empty()).map(|r| r.to_string())
            }
            _ => None,
        };
        findings.push(Finding { subject, evaluation, explain, steps, removal });
    }

    findings.sort_by(|a, b| {
        rank(a.confidence())
            .cmp(&rank(b.confidence()))
            .then(max_severity(b).cmp(&max_severity(a)))
            .then(a.subject.title.to_lowercase().cmp(&b.subject.title.to_lowercase()))
    });
    camera_mic.sort_by_key(|s| {
        std::cmp::Reverse(match s.facts.get(keys::LAST_USED_MILLIS) {
            Some(psg_core::FactValue::Number(n)) => *n,
            _ => 0,
        })
    });

    Report {
        started_millis,
        finished_millis,
        deep: raw.deep,
        bundle_version: bundle.version,
        computer: raw.computer.clone(),
        findings,
        checked,
        gaps: raw.gaps.clone(),
        camera_mic,
    }
}

fn rank(c: Confidence) -> u8 {
    match c {
        Confidence::Confirmed => 0,
        Confidence::VeryLikely => 1,
        Confidence::Possible => 2,
        Confidence::Unlikely => 3,
    }
}

fn max_severity(f: &Finding) -> Option<Severity> {
    f.evaluation.verdict.concerning().iter().map(|s| s.severity).max()
}
