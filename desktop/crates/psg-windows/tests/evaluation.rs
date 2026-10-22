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
//!
//! These are synthetic inventories, not installs on real PCs: they measure
//! the matching and scoring, not the collectors. `PSG_WRITE_EVAL=1` rewrites
//! `eval/RESULTS.md` with the numbers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use psg_core::{Confidence, DetectionEngine, RuleBundleParser};
use psg_windows::raw::{
    AutostartEntry, CameraMicUse, CertInfo, ExtensionRecord, InstalledProgram, ProcessInfo, ServiceInfo,
    SignatureInfo,
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
        location: "wmi".into(),
        place: "root\\subscription".into(),
        name: "SCM Event Log Consumer".into(),
        command: "powershell -w hidden -enc ...".into(),
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into(),
    });
    v.push(Setup { name: "Hidden WMI start-up trigger", raw: r, known_limit: false });

    let mut r = clean_pc();
    r.autostarts.push(AutostartEntry {
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
        "| Unknown setups caught by behaviour alone | {caught} of {expected_catchable} ({:.0}%), plus {} known limit(s) listed below |\n\n",
        pct(caught, expected_catchable),
        setups.iter().filter(|s| s.known_limit).count()
    ));
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
}
