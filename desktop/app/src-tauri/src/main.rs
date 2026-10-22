//! Phone Spy Guard for Windows.
//!
//! The window, the tray icon and the 15-minute change watch. The logic lives
//! in `core.rs`; this file wires it to the UI.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod accounts;
mod core;
mod device_key;
mod rules;
mod store;
mod system;
mod updater;
mod winsec;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_notification::NotificationExt;

use crate::core::{CheckResult, Core, Status, Timeline, WATCH_INTERVAL_MILLIS};
use crate::store::now_millis;

struct Shared {
    core: Mutex<Core>,
    checking: AtomicBool,
    hidden_once: AtomicBool,
    /// With the app lock on, nothing sensitive is handed to the window until
    /// the owner confirms with Windows Hello or their password.
    locked: AtomicBool,
    updating: AtomicBool,
}

type AppState<'a> = State<'a, Arc<Shared>>;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, Core> {
    shared.core.lock().unwrap_or_else(|p| p.into_inner())
}

/// Collect (slow, no lock held), then score and log (fast, under the lock).
fn run_check(shared: &Shared, deep: bool) -> Result<CheckResult, String> {
    if shared.checking.swap(true, Ordering::SeqCst) {
        return Err("A check is already running.".into());
    }
    let result = {
        let started = now_millis();
        let raw = {
            let mut raw = psg_windows::collect::collect(false);
            if deep {
                match system::deep_collect() {
                    Ok(extra) => raw.merge_deep(extra),
                    Err(e) => raw.gaps.push(psg_windows::Gap {
                        area: "Deep check".into(),
                        reason: e,
                        needs_deep_check: true,
                    }),
                }
            }
            without_self(raw)
        };
        lock(shared).check(raw, started)
    };
    shared.checking.store(false, Ordering::SeqCst);
    result
}

/// Look for new signed rules (download outside the lock, install and load
/// under it).
fn run_rule_update(shared: &Shared, url: &str) -> Result<String, String> {
    if shared.updating.swap(true, Ordering::SeqCst) {
        return Err("A rule check is already running.".into());
    }
    let (dir, version) = {
        let core = lock(shared);
        (core.data_dir().to_path_buf(), core.installed_rules_version())
    };
    let result = updater::download(&updater::Https, url, rules::TRUSTED_KEYS, &dir, version);
    let out = lock(shared).finish_rule_check(result, url, now_millis());
    shared.updating.store(false, Ordering::SeqCst);
    out
}

/// The app's own start-up entry and process are not findings.
fn without_self(mut raw: psg_windows::RawInventory) -> psg_windows::RawInventory {
    if let Ok(me) = std::env::current_exe() {
        let me = me.display().to_string().to_lowercase();
        raw.autostarts.retain(|a| a.path.to_lowercase() != me);
        raw.processes.retain(|p| p.path.to_lowercase() != me);
    }
    raw
}

fn notify(app: &AppHandle, alerts: &[String]) {
    if alerts.is_empty() {
        return;
    }
    let discreet = app.try_state::<Arc<Shared>>().map(|s| lock(&s).state().discreet).unwrap_or(true);
    // Discreet (the default): never name a finding where someone looking at
    // the screen, or a program reading notifications, could see it.
    let (title, body) = if discreet {
        ("Device check".to_string(), "A check finished. Open the app for details.".to_string())
    } else if alerts.len() == 1 {
        ("Phone Spy Guard found something".to_string(), alerts[0].clone())
    } else {
        ("Phone Spy Guard found something".to_string(), format!("{} and {} more", alerts[0], alerts.len() - 1))
    };
    let _ = app.notification().builder().title(title).body(body).show();
}

fn names(discreet: bool) -> (&'static str, &'static str) {
    if discreet {
        ("Device Check", "Device check is running")
    } else {
        ("Phone Spy Guard", "Phone Spy Guard is watching this PC")
    }
}

/// The window and tray icon: the shield, or in discreet mode a plain grey
/// gear, as the phone app's discreet launcher icon does. 64x64 RGBA.
fn icon(discreet: bool) -> tauri::image::Image<'static> {
    static SHIELD: &[u8] = include_bytes!("../data/shield-64.rgba");
    static GEAR: &[u8] = include_bytes!("../data/discreet-64.rgba");
    tauri::image::Image::new(if discreet { GEAR } else { SHIELD }, 64, 64)
}

fn apply_names(app: &AppHandle, discreet: bool) {
    let (title, tooltip) = names(discreet);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_title(title);
        let _ = w.set_icon(icon(discreet));
    }
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(tooltip));
        let _ = tray.set_icon(Some(icon(discreet)));
    }
}

fn hwnd(app: &AppHandle) -> isize {
    #[cfg(windows)]
    {
        app.get_webview_window("main").and_then(|w| w.hwnd().ok()).map(|h| h.0 as isize).unwrap_or(0)
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        0
    }
}

/// Windows Hello or the account password, off the UI thread.
async fn confirm_owner(app: &AppHandle, message: &str) -> Result<(), String> {
    let handle = hwnd(app);
    let message = message.to_string();
    let ok = tauri::async_runtime::spawn_blocking(move || winsec::verify_owner(handle, &message))
        .await
        .map_err(|e| e.to_string())??;
    if ok {
        Ok(())
    } else {
        Err("Not confirmed, so nothing was changed.".into())
    }
}

fn unlocked(state: &Shared) -> Result<(), String> {
    if state.locked.load(Ordering::SeqCst) {
        Err("Locked".into())
    } else {
        Ok(())
    }
}

// --- commands the UI calls --------------------------------------------------

#[tauri::command]
fn get_status(state: AppState<'_>) -> Status {
    let status = lock(&state).status();
    if state.locked.load(Ordering::SeqCst) {
        status.redacted()
    } else {
        status
    }
}

#[tauri::command]
fn get_last_report(state: AppState<'_>) -> Result<Option<serde_json::Value>, String> {
    unlocked(&state)?;
    Ok(lock(&state).last_report())
}

#[tauri::command]
fn is_locked(state: AppState<'_>) -> bool {
    state.locked.load(Ordering::SeqCst)
}

#[tauri::command]
async fn unlock(app: AppHandle, state: AppState<'_>) -> Result<(), String> {
    confirm_owner(&app, "Confirm it's you to open the app.").await?;
    state.locked.store(false, Ordering::SeqCst);
    Ok(())
}

/// Hide the window at once. With the app lock on, it locks too.
#[tauri::command]
fn quick_exit(app: AppHandle, state: AppState<'_>) {
    if lock(&state).state().app_lock {
        state.locked.store(true, Ordering::SeqCst);
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
}

#[tauri::command]
async fn check_now(app: AppHandle, state: AppState<'_>, deep: bool) -> Result<CheckResult, String> {
    unlocked(&state)?;
    let shared = state.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || run_check(&shared, deep))
        .await
        .map_err(|e| e.to_string())??;
    notify(&app, &result.alerts);
    Ok(result)
}

/// "I set this up" lowers a finding, so Windows must confirm the owner first
/// (security review H5). "I didn't do this" needs no confirmation.
#[tauri::command]
async fn answer(
    app: AppHandle,
    state: AppState<'_>,
    subject_id: String,
    title: String,
    i_did_this: bool,
) -> Result<(), String> {
    unlocked(&state)?;
    if i_did_this {
        confirm_owner(&app, &format!("Confirm it's you before marking \"{title}\" as something you set up.")).await?;
    }
    lock(&state).answer(&subject_id, &title, i_did_this)
}

#[tauri::command]
fn add_note(state: AppState<'_>, text: String) -> Result<(), String> {
    unlocked(&state)?;
    let text = text.trim();
    if text.is_empty() || text.len() > 2000 {
        return Err("A note must be between 1 and 2000 characters.".into());
    }
    lock(&state).note(text)
}

#[tauri::command]
fn get_timeline(state: AppState<'_>) -> Result<Timeline, String> {
    unlocked(&state)?;
    Ok(lock(&state).timeline())
}

#[tauri::command]
fn make_checkpoint(state: AppState<'_>) -> Result<String, String> {
    unlocked(&state)?;
    lock(&state).checkpoint()
}

#[tauri::command]
async fn start_new_timeline(app: AppHandle, state: AppState<'_>) -> Result<(), String> {
    unlocked(&state)?;
    confirm_owner(&app, "Confirm it's you to keep the damaged timeline aside and start a new one.").await?;
    lock(&state).start_new_timeline()
}

#[tauri::command]
fn export_timeline(app: AppHandle, state: AppState<'_>) -> Result<String, String> {
    unlocked(&state)?;
    let dir = app
        .path()
        .document_dir()
        .or_else(|_| app.path().home_dir())
        .map_err(|e| e.to_string())?;
    let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
    lock(&state).export(&dir, &computer).map(|p| p.display().to_string())
}

/// Turning the watch off is what an abuser would do first, so it needs the
/// owner's confirmation; it is also written to the timeline.
#[tauri::command]
async fn set_watch(app: AppHandle, state: AppState<'_>, enabled: bool) -> Result<(), String> {
    unlocked(&state)?;
    if !enabled {
        confirm_owner(&app, "Confirm it's you to turn the change watch off.").await?;
    }
    lock(&state).set_watch(enabled)
}

#[tauri::command]
async fn set_app_lock(app: AppHandle, state: AppState<'_>, enabled: bool) -> Result<(), String> {
    unlocked(&state)?;
    confirm_owner(&app, if enabled { "Confirm it's you to turn on the app lock." } else { "Confirm it's you to turn off the app lock." })
        .await?;
    lock(&state).set_app_lock(enabled)
}

#[tauri::command]
fn set_discreet(app: AppHandle, state: AppState<'_>, enabled: bool) -> Result<(), String> {
    unlocked(&state)?;
    lock(&state).set_discreet(enabled)?;
    apply_names(&app, enabled);
    Ok(())
}

#[tauri::command]
fn set_start_at_sign_in(state: AppState<'_>, enabled: bool) -> Result<(), String> {
    unlocked(&state)?;
    system::set_start_at_sign_in(enabled)?;
    lock(&state).set_start_at_sign_in(enabled)
}

/// The message check. Runs on this PC only; nothing is sent or saved.
#[tauri::command]
fn check_message(state: AppState<'_>, text: String) -> Result<psg_scam::ScamVerdict, String> {
    unlocked(&state)?;
    if text.trim().is_empty() {
        return Err("Paste a message first.".into());
    }
    if text.len() > 20_000 {
        return Err("That is longer than a message; paste just the message you're unsure about.".into());
    }
    Ok(psg_scam::check(&text))
}

#[tauri::command]
fn account_checkup(state: AppState<'_>) -> Result<&'static [accounts::Step], String> {
    unlocked(&state)?;
    Ok(accounts::steps())
}

#[tauri::command]
fn account_checkup_report(
    state: AppState<'_>,
    answers: std::collections::BTreeMap<String, accounts::Answer>,
) -> Result<accounts::Report, String> {
    unlocked(&state)?;
    Ok(accounts::report(&answers))
}

#[tauri::command]
fn safety_note_seen(state: AppState<'_>) -> Result<(), String> {
    lock(&state).mark_safety_note_seen()
}

#[tauri::command]
async fn check_rule_updates(app: AppHandle, state: AppState<'_>) -> Result<String, String> {
    unlocked(&state)?;
    let url = updater::source().ok_or("No update server is set for this build. Install a rule file instead.")?;
    let shared = state.inner().clone();
    let out = tauri::async_runtime::spawn_blocking(move || run_rule_update(&shared, &url))
        .await
        .map_err(|e| e.to_string())?;
    let _ = app.emit("rules-updated", ());
    out
}

/// Rules the owner brought on a USB stick or downloaded elsewhere, for a PC
/// whose network may be watched. Checked exactly like a download.
#[tauri::command]
fn install_rules_from_file(app: AppHandle, state: AppState<'_>, bundle: String, signature: String) -> Result<String, String> {
    unlocked(&state)?;
    if bundle.len() > 4 * 1024 * 1024 || signature.len() > 64 * 1024 {
        return Err("That is far larger than a rule file.".into());
    }
    let mut core = lock(&state);
    let result = updater::install(rules::TRUSTED_KEYS, core.data_dir(), &bundle, &signature, core.installed_rules_version());
    let out = core.finish_rule_check(result, "file chosen by the owner", now_millis());
    drop(core);
    let _ = app.emit("rules-updated", ());
    out
}

/// Stale rules miss new spyware, so turning updates off needs the owner.
#[tauri::command]
async fn set_auto_rule_updates(app: AppHandle, state: AppState<'_>, enabled: bool) -> Result<(), String> {
    unlocked(&state)?;
    if !enabled {
        confirm_owner(&app, "Confirm it's you to turn automatic rule updates off.").await?;
    }
    lock(&state).set_auto_rule_updates(enabled)
}

#[tauri::command]
fn open_windows_page(page: String) -> Result<(), String> {
    system::open_page(&page)
}

// --- the watch --------------------------------------------------------------

/// Every minute, see whether a watch check is due (FR-DSK-08: within 15 min).
/// Rule updates are looked for on the same timer, once a day.
fn start_watch(app: AppHandle, shared: Arc<Shared>) {
    let started = now_millis();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(60));
        let (enabled, last, update) = {
            let core = lock(&shared);
            (core.state().watch_enabled, core.state().last_run_millis, core.rule_update_due(now_millis(), started))
        };
        if let Some(url) = update {
            if run_rule_update(&shared, &url).is_ok() {
                let _ = app.emit("rules-updated", ());
            }
        }
        if !enabled || now_millis() - last < WATCH_INTERVAL_MILLIS {
            continue;
        }
        match run_check(&shared, false) {
            Ok(result) => {
                notify(&app, &result.alerts);
                let _ = app.emit("check-finished", &result);
            }
            Err(e) => {
                let _ = app.emit("check-failed", e);
            }
        }
    });
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--deep-collect") {
        // The elevated helper: collect, write, exit. No window.
        let out = args.get(i + 1).cloned().unwrap_or_default();
        std::process::exit(system::run_deep_collect(&out));
    }
    let background = args.iter().any(|a| a == "--background");

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(move |app| {
            let dir = app.path().app_local_data_dir()?;
            let core = Core::open(dir).map_err(Box::<dyn std::error::Error>::from)?;
            let (app_lock, discreet) = (core.state().app_lock, core.state().discreet);
            let shared = Arc::new(Shared {
                core: Mutex::new(core),
                checking: AtomicBool::new(false),
                hidden_once: AtomicBool::new(false),
                locked: AtomicBool::new(app_lock),
                updating: AtomicBool::new(false),
            });
            app.manage(shared.clone());

            let open = MenuItem::with_id(app, "open", "Open", true, None::<&str>)?;
            let check = MenuItem::with_id(app, "check", "Check now", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit (stops the watch)", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &check, &quit])?;
            let tray_shared = shared.clone();
            TrayIconBuilder::with_id("main")
                .icon(icon(discreet))
                .tooltip(names(discreet).1)
                .menu(&menu)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "check" => {
                        let app = app.clone();
                        let shared = tray_shared.clone();
                        std::thread::spawn(move || {
                            if let Ok(r) = run_check(&shared, false) {
                                notify(&app, &r.alerts);
                                let _ = app.emit("check-finished", &r);
                            }
                        });
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            start_watch(app.handle().clone(), shared);
            apply_names(app.handle(), discreet);
            if !background {
                show_main(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the watch running in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                let shared = app.state::<Arc<Shared>>();
                let (watching, app_lock, discreet) = {
                    let core = lock(&shared);
                    (core.state().watch_enabled, core.state().app_lock, core.state().discreet)
                };
                if app_lock {
                    shared.locked.store(true, Ordering::SeqCst);
                    let _ = app.emit("locked", ());
                }
                if watching {
                    api.prevent_close();
                    let _ = window.hide();
                    if !shared.hidden_once.swap(true, Ordering::SeqCst) {
                        let (title, body) = if discreet {
                            ("Device check", "Still running in the tray. Use Quit in the tray menu to stop it.")
                        } else {
                            (
                                "Phone Spy Guard is still watching",
                                "It keeps checking every 15 minutes from the tray. Use Quit in the tray menu to stop it.",
                            )
                        };
                        let _ = app.notification().builder().title(title).body(body).show();
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_last_report,
            is_locked,
            unlock,
            quick_exit,
            make_checkpoint,
            start_new_timeline,
            set_app_lock,
            set_discreet,
            check_now,
            answer,
            add_note,
            get_timeline,
            export_timeline,
            set_watch,
            set_start_at_sign_in,
            safety_note_seen,
            open_windows_page,
            check_rule_updates,
            install_rules_from_file,
            set_auto_rule_updates,
            check_message,
            account_checkup,
            account_checkup_report,
        ])
        .run(tauri::generate_context!())
        .expect("Phone Spy Guard failed to start");
}
