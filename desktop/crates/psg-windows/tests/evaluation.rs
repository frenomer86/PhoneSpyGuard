//! The measured part of the thesis evaluation that can run without real
//! malware (security review M6). Three sets, all in `desktop/eval/`:
//!
//! 1. False alarms: 256 common Windows programs (browsers, office, games,
//!    drivers, VPNs, antivirus, assistive tech, near-miss names), each
//!    installed, running and starting with Windows from Program Files with a
//!    valid signature, one PC at a time and then all on one PC.
//! 2. Known products: 75 installs of the listed monitoring, remote-access and
//!    oversight products, named as their installers name them, including a
//!    renamed install that keeps the vendor as publisher.
//! 3. Unknown setups: products not on any list, set up the way stalkerware
//!    and remote-access scams usually are. These test the behaviour rules
//!    alone, the desktop analogue of the spec's held-out families.
//! 4. Stalkerware indicators: every Echap family's servers seen in the DNS
//!    cache and in a program's connection, every one of the 3,228 installer
//!    hashes as a file in Downloads, and 170 everyday host names (including
//!    other apps on the same cloud hosts) that must not match.
//! 5. Windows' own deep start-up entries (LSA packages, print monitors,
//!    netsh helpers, Active Setup) and signed vendor add-ins, which must not
//!    be flagged.
//!
//! These are synthetic inventories, not installs on real PCs: they measure
//! the matching and scoring, not the collectors. `PSG_WRITE_EVAL=1` rewrites
//! `eval/RESULTS.md` with the numbers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use psg_core::{Confidence, DetectionEngine, RuleBundleParser};
use psg_windows::network::{NetIndex, Role};
use psg_windows::raw::{
    AutostartEntry, CameraMicUse, CertInfo, DnsRecord, ExtensionRecord, FoundFile, InstalledProgram, NetConnection,
    ProcessInfo, ServiceInfo, SignatureInfo,
};
use psg_windows::{evaluate, RawInventory, Report};
use serde_json::Value;

const NOW: i64 = 1_792_000_000_000;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn engine() -> DetectionEngine {
    let text = std::fs::read_to_string(root().join("rules/desktop-bundle.json")).unwrap();
    DetectionEngine::new(RuleBundleParser::default().parse(&text).unwrap())
}

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(root().join("eval").join(name)).unwrap()).unwrap()
}

fn clean_pc() -> RawInventory {
    let mut raw = RawInventory { computer: "EVAL".into(), user: "owner".into(), ..Default::default() };
    raw.settings.defender_realtime_enabled = Some(true);
    raw.settings.defender_antivirus_enabled = Some(true);
    raw.settings.rdp_enabled = Some(false);
    raw.settings.admins = Some(Vec::new());
    raw.settings.defender_exclusions = Some(Vec::new());
    raw
}

fn add_program(raw: &mut RawInventory, name: &str, publisher: &str, path: &str, signed: bool) {
    let dir = path.rsplit_once('\\').map(|(d, _)| d).unwrap_or("");
    raw.installed.push(InstalledProgram {
        name: name.into(),
        publisher: publisher.into(),
        version: "1.0".into(),
        install_location: dir.into(),
        install_date: "20260101".into(),
        hive: "HKLM".into(),
    });
    if path.is_empty() {
        return;
    }
    let exe = path.rsplit('\\').next().unwrap_or(path);
    raw.processes.push(ProcessInfo { name: exe.into(), path: path.into(), pid: 1000 + raw.processes.len() as u32 });
    raw.autostarts.push(AutostartEntry {
        since_coverage: 0,
        location: "run_key".into(),
        place: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
        name: name.into(),
        command: format!("\"{path}\" --background"),
        path: path.into(),
    });
    raw.signatures.insert(
        path.to_lowercase(),
        SignatureInfo {
            status: if signed { "signed" } else { "unsigned" }.into(),
            signer: if signed { publisher.into() } else { String::new() },
        },
    );
}

fn flagged(report: &Report) -> Vec<(String, Confidence)> {
    report
        .findings
        .iter()
        .filter(|f| f.confidence() != Confidence::Unlikely)
        .map(|f| (f.subject.id.clone(), f.confidence()))
        .collect()
}

fn run(raw: &RawInventory, engine: &DetectionEngine) -> Report {
    evaluate(raw, engine, None, &BTreeMap::new(), NOW, NOW).report
}

// --- 1. false alarms -----------------------------------------------------------

struct FalseAlarms {
    programs: usize,
    any_flag: Vec<(String, String)>,
    high: Vec<(String, String)>,
    all_on_one_pc: usize,
}

fn false_alarms(engine: &DetectionEngine) -> FalseAlarms {
    let set = load("benign-programs.json");
    let programs = set["programs"].as_array().unwrap();
    let mut out = FalseAlarms { programs: programs.len(), any_flag: Vec::new(), high: Vec::new(), all_on_one_pc: 0 };
    assert!(flagged(&run(&clean_pc(), engine)).is_empty(), "a clean PC must have no findings");
    let mut everything = clean_pc();
    for p in programs {
        let (name, publisher, path) =
            (p["name"].as_str().unwrap(), p["publisher"].as_str().unwrap(), p["path"].as_str().unwrap());
        let mut raw = clean_pc();
        add_program(&mut raw, name, publisher, path, true);
        add_program(&mut everything, name, publisher, path, true);
        for (id, c) in flagged(&run(&raw, engine)) {
            let line = (name.to_string(), format!("{id} {}", c.as_str()));
            if matches!(c, Confidence::Confirmed | Confidence::VeryLikely) {
                out.high.push(line.clone());
            }
            out.any_flag.push(line);
        }
    }
    out.all_on_one_pc = flagged(&run(&everything, engine)).len();
    out
}

// --- 2. known products -------------------------------------------------------------

struct Known {
    misses: Vec<String>,
    by_list: BTreeMap<String, (usize, usize)>,
}

fn known_products(engine: &DetectionEngine) -> Known {
    let set = load("known-products.json");
    let cases = set["cases"].as_array().unwrap();
    let mut out = Known { misses: Vec::new(), by_list: BTreeMap::new() };
    for c in cases {
        let (list, ind, name, publisher, path) = (
            c["list"].as_str().unwrap(),
            c["indicator"].as_str().unwrap(),
            c["name"].as_str().unwrap(),
            c["publisher"].as_str().unwrap(),
            c["path"].as_str().unwrap(),
        );
        let mut raw = clean_pc();
        // Vendors sign their own binaries; the match must not depend on it.
        add_program(&mut raw, name, publisher, path, !publisher.is_empty());
        let report = run(&raw, engine);
        let finding = report.findings.iter().find(|f| f.subject.id == format!("product:{ind}"));
        let expected = match list {
            "monitoring" => Confidence::Confirmed,
            _ => Confidence::Possible,
        };
        let ok = finding.is_some_and(|f| f.confidence() <= expected);
        let entry = out.by_list.entry(list.to_string()).or_default();
        entry.0 += 1;
        if ok {
            entry.1 += 1;
        } else {
            out.misses.push(format!(
                "{name} ({ind}): got {}",
                finding.map(|f| f.confidence().as_str()).unwrap_or("no product match")
            ));
        }
    }
    out
}

// --- 4. stalkerware indicators --------------------------------------------------------

struct Echap {
    families: usize,
    with_servers: usize,
    connection_confirmed: usize,
    lookup_very_likely: usize,
    /// Families whose every server name is also their shop's name, so a
    /// lookup can only count as a shop visit.
    shop_named_only: Vec<String>,
    misses: Vec<String>,
    hashes: usize,
    hashes_found: usize,
    benign_names: usize,
    benign_flags: Vec<String>,
}

fn finding_for<'a>(report: &'a Report, id: &str) -> Option<&'a psg_windows::Finding> {
    report.findings.iter().find(|f| f.subject.id == id)
}

fn echap(engine: &DetectionEngine) -> Echap {
    let families = &engine.bundle().indicators.stalkerware;
    let index = NetIndex::new(families);
    let mut out = Echap {
        families: families.len(),
        with_servers: 0,
        connection_confirmed: 0,
        lookup_very_likely: 0,
        shop_named_only: Vec::new(),
        misses: Vec::new(),
        hashes: 0,
        hashes_found: 0,
        benign_names: 0,
        benign_flags: Vec::new(),
    };
    let spy = "C:\\Users\\owner\\AppData\\Roaming\\WinSvc\\svchelper.exe";
    for f in families.iter().filter(|f| !f.domains.is_empty()) {
        out.with_servers += 1;
        let id = format!("network:{}", f.id);
        let unshadowed = f.domains.iter().find(|d| matches!(index.host(d), Some((_, Role::Server, _))));
        let server = unshadowed.unwrap_or(&f.domains[0]);
        let lookup = DnsRecord { name: server.clone(), data: "198.51.100.20".into(), record_type: 1 };

        let mut raw = clean_pc();
        raw.processes.push(ProcessInfo { name: "svchelper.exe".into(), path: spy.into(), pid: 4242 });
        raw.dns_cache = Some(vec![lookup.clone()]);
        raw.connections = Some(vec![NetConnection {
            remote_address: "198.51.100.20".into(),
            remote_port: 443,
            state: "Established".into(),
            pid: 4242,
        }]);
        match finding_for(&run(&raw, engine), &id).map(|x| x.confidence()) {
            Some(Confidence::Confirmed) => out.connection_confirmed += 1,
            got => out.misses.push(format!("{} connection to {server}: {got:?}", f.name)),
        }

        if unshadowed.is_none() {
            out.shop_named_only.push(f.name.clone());
            continue;
        }
        let mut raw = clean_pc();
        raw.dns_cache = Some(vec![lookup]);
        match finding_for(&run(&raw, engine), &id).map(|x| x.confidence()) {
            Some(c) if c <= Confidence::VeryLikely => out.lookup_very_likely += 1,
            got => out.misses.push(format!("{} lookup of {server}: {got:?}", f.name)),
        }
    }

    // Every installer hash, each as its own file in Downloads, on one PC.
    let mut raw = clean_pc();
    for (i, h) in families.iter().flat_map(|f| &f.sha256).enumerate() {
        raw.apk_files.push(FoundFile {
            path: format!("C:\\Users\\owner\\Downloads\\app-{i}.apk"),
            size: 1_000_000,
            sha256: h.to_uppercase(),
            modified_millis: Some(NOW),
        });
    }
    out.hashes = raw.apk_files.len();
    let report = run(&raw, engine);
    out.hashes_found = report
        .findings
        .iter()
        .filter(|f| f.subject.id.starts_with("file:") && f.confidence() <= Confidence::VeryLikely)
        .count();

    // Everyday names, looked up and connected to by a browser and by an app.
    let set = load("benign-domains.json");
    let names: Vec<&str> = set["domains"].as_array().unwrap().iter().map(|d| d.as_str().unwrap()).collect();
    out.benign_names = names.len();
    let mut raw = clean_pc();
    raw.processes.push(ProcessInfo { name: "chrome.exe".into(), path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".into(), pid: 10 });
    raw.processes.push(ProcessInfo { name: "Teams.exe".into(), path: "C:\\Program Files\\Teams\\Teams.exe".into(), pid: 11 });
    let mut dns = Vec::new();
    let mut conns = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let ip = format!("198.18.{}.{}", i / 250, i % 250 + 1);
        dns.push(DnsRecord { name: n.to_string(), data: ip.clone(), record_type: 1 });
        for pid in [10, 11] {
            conns.push(NetConnection { remote_address: ip.clone(), remote_port: 443, state: "Established".into(), pid });
        }
    }
    raw.dns_cache = Some(dns);
    raw.connections = Some(conns);
    out.benign_flags = flagged(&run(&raw, engine)).into_iter().map(|(id, c)| format!("{id} {}", c.as_str())).collect();
    out
}

// --- 5. Windows' own deep start-up entries -----------------------------------------------

fn deep_defaults_pc() -> RawInventory {
    let mut raw = clean_pc();
    let sys = "C:\\Windows\\System32\\";
    let mut add = |location: &str, name: &str, path: &str, signer: &str| {
        raw.autostarts.push(AutostartEntry {
            since_coverage: 1,
            location: location.into(),
            place: format!("eval\\{location}"),
            name: name.into(),
            command: path.into(),
            path: path.into(),
        });
        raw.signatures.insert(path.to_lowercase(), SignatureInfo { status: "signed".into(), signer: signer.into() });
    };
    for m in ["msv1_0", "kerberos", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "scecli"] {
        add("lsa", m, &format!("{sys}{m}.dll"), "Microsoft Windows");
    }
    for (n, d) in [("Local Port", "localspl.dll"), ("Standard TCP/IP Port", "tcpmon.dll"), ("USB Monitor", "usbmon.dll"), ("WSD Port", "WSDMon.dll")] {
        add("print_monitor", n, &format!("{sys}{d}"), "Microsoft Windows");
    }
    add("print_monitor", "HP Standard TCP/IP Port", &format!("{sys}hpinkcom.dll"), "HP Inc.");
    for (n, d) in [("2", "ifmon.dll"), ("4", "rasmontr.dll"), ("authfwcfg", "authfwcfg.dll"), ("dhcpclient", "dhcpcmonitor.dll"), ("wlancfg", "wlancfg.dll")] {
        add("netsh", n, &format!("{sys}{d}"), "Microsoft Windows");
    }
    add("active_setup", "Windows Media Player", &format!("{sys}unregmp2.exe"), "Microsoft Windows");
    add("active_setup", "Google Chrome", "C:\\Program Files\\Google\\Chrome\\Application\\120.0\\Installer\\chrmstp.exe", "Google LLC");
    add("shell_extension", "OneDrive", "C:\\Users\\owner\\AppData\\Local\\Microsoft\\OneDrive\\FileSyncShell64.dll", "Microsoft Corporation");
    add("com_hijack", "OneDrive sync", "C:\\Users\\owner\\AppData\\Local\\Microsoft\\OneDrive\\FileCoAuthLib64.dll", "Microsoft Corporation");
    add("bho", "Adobe Acrobat", "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroIEHelperShim.dll", "Adobe Inc.");
    add("boot_execute", "BootExecute", &format!("{sys}aswBoot.exe"), "Avast Software s.r.o.");
    raw
}

// --- 3. unknown setups ----------------------------------------------------------------

struct Setup {
    name: &'static str,
    raw: RawInventory,
    /// The behaviour rules are not expected to catch this one; it is listed
    /// to show the limit honestly.
    known_limit: bool,
}

fn unknown_setups() -> Vec<Setup> {
    let appdata = "C:\\Users\\owner\\AppData\\Roaming\\SysCache\\syshost.exe";
    let mut v = Vec::new();

    let mut r = clean_pc();
    add_program(&mut r, "System Cache Host", "", appdata, false);
    v.push(Setup { name: "Unsigned keylogger in AppData that starts with Windows", raw: r, known_limit: false });

    let mut r = clean_pc();
    add_program(&mut r, "Audio Service", "", appdata, false);
    r.camera_mic.push(CameraMicUse {
        device: "microphone".into(),
        app: appdata.into(),
        packaged: false,
        last_start_millis: Some(NOW - 3_600_000),
        last_stop_millis: Some(NOW - 3_000_000),
    });
    v.push(Setup { name: "Unsigned program in AppData recording the microphone", raw: r, known_limit: false });

    let mut r = clean_pc();
    r.extensions.push(ExtensionRecord {
        browser: "chrome".into(),
        profile: "Default".into(),
        id: "abcdefghijklmnopabcdefghijklmnop".into(),
        name: "PDF Helper".into(),
        version: "1.0".into(),
        all_sites: true,
        outside_store: true,
        force_installed: false,
        enabled: true,
        permissions: vec!["<all_urls>".into(), "webRequest".into(), "cookies".into()],
    });
    v.push(Setup { name: "Sideloaded browser extension reading every site", raw: r, known_limit: false });

    let mut r = clean_pc();
    r.extensions.push(ExtensionRecord {
        browser: "edge".into(),
        profile: "Default".into(),
        id: "ponmlkjihgfedcbaponmlkjihgfedcba".into(),
        name: "Sync Assistant".into(),
        version: "2.1".into(),
        all_sites: true,
        outside_store: false,
        force_installed: true,
        enabled: true,
        permissions: vec!["<all_urls>".into()],
    });
    v.push(Setup { name: "Browser extension forced on by policy on a personal PC", raw: r, known_limit: false });

    let mut r = clean_pc();
    r.settings.user_root_certs.push(CertInfo { thumbprint: "AB".repeat(20), subject: "CN=Secure Gateway CA".into() });
    r.settings.proxy_enabled = true;
    r.settings.proxy_server = "203.0.113.7:8080".into();
    v.push(Setup { name: "Added root certificate plus a remote proxy (reads HTTPS)", raw: r, known_limit: false });

    let mut r = clean_pc();
    r.autostarts.push(AutostartEntry {
        since_coverage: 0,
        location: "wmi".into(),
        place: "root\\subscription".into(),
        name: "SCM Event Log Consumer".into(),
        command: "powershell -w hidden -enc ...".into(),
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into(),
    });
    v.push(Setup { name: "Hidden WMI start-up trigger", raw: r, known_limit: false });

    let mut r = clean_pc();
    r.autostarts.push(AutostartEntry {
        since_coverage: 0,
        location: "ifeo".into(),
        place: "HKLM\\...\\Image File Execution Options\\sethc.exe".into(),
        name: "sethc.exe".into(),
        command: "C:\\Windows\\System32\\cmd.exe".into(),
        path: "C:\\Windows\\System32\\cmd.exe".into(),
    });
    v.push(Setup { name: "Program replacement (IFEO debugger) on a Windows tool", raw: r, known_limit: false });

    let mut r = clean_pc();
    r.settings.defender_realtime_enabled = Some(false);
    r.settings.defender_exclusions = Some(vec!["C:\\Users\\owner\\AppData\\Roaming\\SysCache".into()]);
    v.push(Setup { name: "Defender switched off with an exclusion for a hidden folder", raw: r, known_limit: false });

    let mut r = clean_pc();
    let rat = "C:\\Program Files\\HelpDesk Connect\\hdc.exe";
    add_program(&mut r, "HelpDesk Connect", "", rat, false);
    r.services.push(ServiceInfo { name: "HDCService".into(), display_name: "HelpDesk Connect".into(), path: rat.into(), start: 2, driver: false });
    r.settings.extra_admins_for_eval();
    v.push(Setup { name: "Unlisted remote-access tool from a scam call, plus a new admin account", raw: r, known_limit: false });

    let mut r = clean_pc();
    r.settings.extra_admins_for_eval();
    r.settings.accounts = Some(vec![psg_windows::raw::LocalAccount {
        name: "support".into(),
        sid: "S-1-5-21-1-2-3-1005".into(),
        enabled: true,
        last_logon_millis: None,
    }]);
    r.settings.hidden_from_sign_in = vec!["support".into()];
    v.push(Setup { name: "Administrator account hidden from the sign-in screen", raw: r, known_limit: false });

    let hook = |location: &str, name: &str, path: &str, status: &str, signer: &str| {
        let mut r = clean_pc();
        r.autostarts.push(AutostartEntry {
            since_coverage: 1,
            location: location.into(),
            place: format!("eval\\{location}"),
            name: name.into(),
            command: path.into(),
            path: path.into(),
        });
        r.signatures.insert(path.to_lowercase(), SignatureInfo { status: status.into(), signer: signer.into() });
        r
    };
    v.push(Setup {
        name: "Unsigned DLL loaded into every program (AppInit_DLLs)",
        raw: hook("appinit", "AppInit_DLLs", "C:\\ProgramData\\WinSvc\\inject.dll", "unsigned", ""),
        known_limit: false,
    });
    v.push(Setup {
        name: "Unsigned password filter in the LSA (reads every new password)",
        raw: hook("lsa", "pwfilter", "C:\\Windows\\System32\\pwfilter.dll", "unsigned", ""),
        known_limit: false,
    });
    v.push(Setup {
        name: "COM hijack for this user to an unsigned DLL in AppData",
        raw: hook("com_hijack", "Thumbnail Cache", "C:\\Users\\owner\\AppData\\Roaming\\thumbcache.dll", "unsigned", ""),
        known_limit: false,
    });
    v.push(Setup {
        name: "Windows tool restarted whenever spyware is closed (SilentProcessExit)",
        raw: hook("silent_exit", "runs when monitor.exe exits", "C:\\Windows\\System32\\cmd.exe", "signed", "Microsoft Windows"),
        known_limit: false,
    });

    let mut r = clean_pc();
    let signed = "C:\\Program Files\\FamilyView\\fview.exe";
    add_program(&mut r, "FamilyView Monitor", "FamilyView Software Ltd", signed, true);
    v.push(Setup {
        name: "Signed, unlisted commercial monitoring app in Program Files",
        raw: r,
        known_limit: true,
    });
    v
}

trait EvalSettings {
    fn extra_admins_for_eval(&mut self);
}

impl EvalSettings for psg_windows::raw::SettingsRaw {
    fn extra_admins_for_eval(&mut self) {
        self.admins = Some(vec![psg_windows::raw::AdminAccount {
            name: "support".into(),
            sid: "S-1-5-21-1-2-3-1005".into(),
            object_class: "User".into(),
            is_current_user: false,
        }]);
    }
}

#[test]
fn evaluation() {
    let engine = engine();
    let fa = false_alarms(&engine);
    let known = known_products(&engine);
    let ec = echap(&engine);
    let deep_defaults = flagged(&run(&deep_defaults_pc(), &engine));
    let setups = unknown_setups();
    let mut unknown_rows = Vec::new();
    let (mut caught, mut expected_catchable) = (0, 0);
    for s in &setups {
        let report = run(&s.raw, &engine);
        let worst = report.findings.iter().map(|f| f.confidence()).min().unwrap_or(Confidence::Unlikely);
        let hit = worst != Confidence::Unlikely;
        if !s.known_limit {
            expected_catchable += 1;
            caught += hit as usize;
        }
        unknown_rows.push((s.name, worst, s.known_limit));
    }

    let pct = |a: usize, b: usize| if b == 0 { 100.0 } else { 100.0 * a as f64 / b as f64 };
    let mut md = String::new();
    md.push_str("# Desktop detection evaluation\n\n");
    md.push_str("Generated by `cargo test -p psg-windows --test evaluation` with `PSG_WRITE_EVAL=1`, from the signed rule bundle in `rules/`. These are synthetic inventories: they measure the matching and scoring rules, not the Windows collectors and not real malware on real PCs. The spec's full evaluation (real stalkerware families, the Play top 500 on phones, MVT test material) still has to be run on devices.\n\nRead the known-product row with care: the product names below were written by the same person who wrote the indicator lists, so 100% shows that matching works on names as installers record them, not that the lists cover every product. The first run of this evaluation flagged two common programs (Radmin VPN, and a game whose publisher name contains the letters of Atera); both were fixed by matching publishers at word starts and narrowing the Radmin token, and the set is kept so they stay fixed.\n\n");
    md.push_str("| Set | Result |\n|---|---|\n");
    md.push_str(&format!(
        "| False alarms, {} common programs one PC each | {} flagged at any level ({:.1}%), {} rated Very likely or Confirmed |\n",
        fa.programs,
        fa.any_flag.len(),
        pct(fa.any_flag.len(), fa.programs),
        fa.high.len()
    ));
    md.push_str(&format!("| All {} programs on one PC | {} findings |\n", fa.programs, fa.all_on_one_pc));
    for (list, (n, ok)) in &known.by_list {
        md.push_str(&format!("| Known products: {list} | {ok} of {n} identified ({:.0}%) |\n", pct(*ok, *n)));
    }
    md.push_str(&format!(
        "| Unknown setups caught by behaviour alone | {caught} of {expected_catchable} ({:.0}%), plus {} known limit(s) listed below |\n",
        pct(caught, expected_catchable),
        setups.iter().filter(|s| s.known_limit).count()
    ));
    md.push_str(&format!(
        "| Stalkerware families with server names (of {} imported from Echap) | {} |\n",
        ec.families, ec.with_servers
    ));
    let testable = ec.with_servers - ec.shop_named_only.len();
    md.push_str(&format!(
        "| A program connected to a family's server | {} of {} Confirmed ({:.0}%) |\n",
        ec.connection_confirmed,
        ec.with_servers,
        pct(ec.connection_confirmed, ec.with_servers)
    ));
    md.push_str(&format!(
        "| A family's server in the DNS cache only | {} of {testable} Very likely or higher ({:.0}%) |\n",
        ec.lookup_very_likely,
        pct(ec.lookup_very_likely, testable)
    ));
    md.push_str(&format!(
        "| Known installer files (.apk) in Downloads | {} of {} found ({:.0}%) |\n",
        ec.hashes_found,
        ec.hashes,
        pct(ec.hashes_found, ec.hashes)
    ));
    md.push_str(&format!(
        "| Everyday host names looked up and connected to | {} names, {} findings |\n",
        ec.benign_names,
        ec.benign_flags.len()
    ));
    md.push_str(&format!(
        "| Windows' own deep start-up entries and signed vendor add-ins | {} findings |\n\n",
        deep_defaults.len()
    ));
    if !ec.shop_named_only.is_empty() {
        md.push_str(&format!(
            "Families whose only server names are also their shop's website, so a DNS lookup alone reads as a shop visit (Possible); a program other than a browser connecting there is still Confirmed: {}.\n\nEchap lists some openly sold parental-control apps as stalkerware (Bark, for example). A visit to their websites is rated Possible, with wording that says it may be innocent.\n\n",
            ec.shop_named_only.join(", ")
        ));
    }
    if !fa.any_flag.is_empty() {
        md.push_str("## Programs from the common set that were flagged\n\n");
        for (n, why) in &fa.any_flag {
            md.push_str(&format!("- {n}: {why}\n"));
        }
        md.push('\n');
    }
    if !known.misses.is_empty() {
        md.push_str("## Known products missed\n\n");
        for m in &known.misses {
            md.push_str(&format!("- {m}\n"));
        }
        md.push('\n');
    }
    md.push_str("## Unknown setups\n\n| Setup | Verdict |\n|---|---|\n");
    for (name, c, limit) in &unknown_rows {
        md.push_str(&format!("| {name}{} | {} |\n", if *limit { " (known limit)" } else { "" }, c.as_str()));
    }
    md.push_str("\nThe known limit is real: a signed commercial monitoring product that is not on the list, installed in Program Files and doing nothing else unusual, looks like any other program. Only the indicator list, a hash match, or the camera/microphone and network records catch it. Keeping the list current matters as much as the rules.\n");

    if std::env::var("PSG_WRITE_EVAL").is_ok() {
        std::fs::write(root().join("eval/RESULTS.md"), &md).unwrap();
    }
    println!("{md}");

    // The gates: every listed product found, nothing common rated high,
    // fewer than 1% of common programs flagged at all, and the spec's 80%
    // for setups no list knows about.
    assert!(known.misses.is_empty(), "{:?}", known.misses);
    assert!(fa.high.is_empty(), "{:?}", fa.high);
    assert!(pct(fa.any_flag.len(), fa.programs) < 1.0, "{:?}", fa.any_flag);
    assert!(pct(caught, expected_catchable) >= 80.0, "{unknown_rows:?}");
    // Every testable Echap family and every installer hash is found, and
    // no everyday name or Windows default is flagged.
    assert!(ec.misses.is_empty(), "{:?}", ec.misses);
    assert_eq!(ec.connection_confirmed, ec.with_servers);
    assert_eq!(ec.hashes_found, ec.hashes);
    assert!(ec.hashes >= 3000, "the full Echap sample set is in the bundle");
    assert!(ec.benign_flags.is_empty(), "{:?}", ec.benign_flags);
    assert!(deep_defaults.is_empty(), "{deep_defaults:?}");
}
