//! The few things the app does to Windows itself, all on the owner's click:
//! ask for administrator rights for the optional deep check, open a Windows
//! settings page, and (if the owner turns it on) start the watch at sign-in.

#[cfg(windows)]
use std::process::Command;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use psg_windows::RawInventory;

#[cfg(windows)]
fn system32(file: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| "C:\\Windows".into());
    root.join("System32").join(file)
}

/// How long Windows' administrator prompt may wait for an answer, and how
/// long the elevated collection may run, before the deep check gives up.
#[cfg_attr(not(windows), allow(dead_code))]
pub const PROMPT_LIMIT: Duration = Duration::from_secs(180);
#[cfg_attr(not(windows), allow(dead_code))]
pub const RUN_LIMIT: Duration = Duration::from_secs(480);

/// Where the deep check is, for the progress line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum DeepPhase {
    /// Windows' administrator prompt is showing (or waiting in the taskbar).
    Prompt,
    /// The owner said yes; the elevated helper is collecting.
    Running,
}

/// Run this same program elevated with `--deep-collect <file>` and read back
/// what it collected (NFR-DSK-03: elevation only for the optional deep check).
///
/// The prompt is owned by the app's window (`owner`), so Windows shows it in
/// front instead of as a flashing taskbar button. Declining, `cancel`, or
/// running past [`PROMPT_LIMIT`] / [`RUN_LIMIT`] all return an error; the
/// normal check's results are kept either way.
pub fn deep_collect(owner: Option<isize>, cancel: &AtomicBool, phase: &dyn Fn(DeepPhase)) -> Result<RawInventory, String> {
    #[cfg(windows)]
    {
        elevated::run(owner, cancel, phase)
    }
    #[cfg(not(windows))]
    {
        let _ = (owner, cancel, phase);
        Err("The deep check needs Windows.".into())
    }
}

/// The marker the app leaves next to the output file when it stops waiting;
/// the helper checks it and does not collect or write.
fn cancel_marker(out: &Path) -> PathBuf {
    let mut m = out.as_os_str().to_owned();
    m.push(".cancel");
    PathBuf::from(m)
}

/// Only files the app itself would name: `psg-deep-*.json`, in an existing
/// directory. The helper runs as administrator, so it must not be pointed at
/// anything else.
fn valid_output(out: &Path) -> bool {
    let name = out.file_name().and_then(|n| n.to_str()).unwrap_or("");
    out.is_absolute()
        && name.starts_with("psg-deep-")
        && name.ends_with(".json")
        && out.parent().is_some_and(|d| d.is_dir())
}

/// The elevated side: collect everything and write it to `out`.
pub fn run_deep_collect(out: &str) -> i32 {
    let out = Path::new(out);
    if !valid_output(out) {
        return 3;
    }
    if cancel_marker(out).exists() {
        return 2;
    }
    let raw = psg_windows::collect::collect(true);
    if cancel_marker(out).exists() {
        return 2;
    }
    let Ok(text) = serde_json::to_string(&raw) else { return 1 };
    // create_new: never follow or overwrite something planted at this path.
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()));
    if written.is_ok() { 0 } else { 1 }
}

#[cfg(windows)]
mod elevated {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::Instant;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE, HWND, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, TerminateProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

    const POLL_MS: u32 = 250;

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// The process handle, as an integer so it can cross threads.
    struct Process(isize);

    impl Process {
        fn handle(&self) -> HANDLE {
            HANDLE(self.0 as *mut _)
        }
        /// Wait up to `ms`; Some(exit code) once it has ended.
        fn wait(&self, ms: u32) -> Option<u32> {
            if unsafe { WaitForSingleObject(self.handle(), ms) } != WAIT_OBJECT_0 {
                return None;
            }
            let mut code = 1u32;
            let _ = unsafe { GetExitCodeProcess(self.handle(), &mut code) };
            Some(code)
        }
        fn stop(&self) {
            // May be refused for an elevated process; the cancel marker stops it anyway.
            let _ = unsafe { TerminateProcess(self.handle(), 2) };
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.handle()) };
        }
    }

    /// ShellExecuteEx blocks until the prompt is answered, so it runs on its
    /// own thread and the caller can stop waiting.
    fn launch(exe: PathBuf, out: PathBuf, owner: Option<isize>) -> mpsc::Receiver<Result<Process, windows::core::Error>> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let verb = wide("runas".as_ref());
            let file = wide(exe.as_os_str());
            let mut params = std::ffi::OsString::from("--deep-collect \"");
            params.push(out.as_os_str());
            params.push("\"");
            let params = wide(&params);
            let mut info = SHELLEXECUTEINFOW {
                cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
                fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
                hwnd: HWND(owner.unwrap_or(0) as *mut _),
                lpVerb: PCWSTR(verb.as_ptr()),
                lpFile: PCWSTR(file.as_ptr()),
                lpParameters: PCWSTR(params.as_ptr()),
                nShow: 0, // SW_HIDE: the helper has no window anyway
                ..Default::default()
            };
            let result = unsafe { ShellExecuteExW(&mut info) }.and_then(|()| {
                if info.hProcess.is_invalid() {
                    Err(windows::core::Error::from_thread())
                } else {
                    Ok(Process(info.hProcess.0 as isize))
                }
            });
            let _ = tx.send(result);
        });
        rx
    }

    /// Stop waiting: tell the helper not to collect or write, and tidy up
    /// once it is gone (in the background, so the app is not held).
    fn abandon(out: PathBuf, rx: Option<mpsc::Receiver<Result<Process, windows::core::Error>>>, process: Option<Process>) {
        let _ = std::fs::write(cancel_marker(&out), b"");
        if let Some(p) = &process {
            p.stop();
        }
        std::thread::spawn(move || {
            let process = process.or_else(|| rx.and_then(|rx| rx.recv().ok()).and_then(Result::ok));
            if let Some(p) = process {
                p.wait(RUN_LIMIT.as_millis() as u32);
            }
            let _ = std::fs::remove_file(&out);
            let _ = std::fs::remove_file(cancel_marker(&out));
        });
    }

    pub fn run(owner: Option<isize>, cancel: &AtomicBool, phase: &dyn Fn(DeepPhase)) -> Result<RawInventory, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let out = std::env::temp_dir().join(format!("psg-deep-{}-{}.json", std::process::id(), crate::store::now_millis()));
        let _ = std::fs::remove_file(cancel_marker(&out));

        phase(DeepPhase::Prompt);
        let rx = launch(exe, out.clone(), owner);
        let asked = Instant::now();
        let process = loop {
            if cancel.load(Ordering::SeqCst) {
                abandon(out, Some(rx), None);
                return Err("Deep check cancelled. The normal check still ran.".into());
            }
            match rx.recv_timeout(Duration::from_millis(POLL_MS as u64)) {
                Ok(Ok(p)) => break p,
                Ok(Err(e)) if e.code() == ERROR_CANCELLED.to_hresult() => {
                    return Err("You said no to Windows' administrator prompt, so the deep check did not run. The normal check still ran.".into())
                }
                Ok(Err(e)) => return Err(format!("Windows could not start the deep check: {}", e.message())),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err("Windows could not start the deep check.".into()),
                Err(mpsc::RecvTimeoutError::Timeout) if asked.elapsed() > PROMPT_LIMIT => {
                    abandon(out, Some(rx), None);
                    return Err(format!(
                        "Windows' administrator prompt was not answered within {} minutes, so the deep check stopped. If you did not see it, look for a flashing shield in the taskbar next time. The normal check still ran.",
                        PROMPT_LIMIT.as_secs() / 60
                    ));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        };

        phase(DeepPhase::Running);
        let started = Instant::now();
        let code = loop {
            if cancel.load(Ordering::SeqCst) {
                abandon(out, None, Some(process));
                return Err("Deep check cancelled. The normal check still ran.".into());
            }
            if let Some(code) = process.wait(POLL_MS) {
                break code;
            }
            if started.elapsed() > RUN_LIMIT {
                abandon(out, None, Some(process));
                return Err(format!(
                    "The deep check took longer than {} minutes and was stopped. The normal check still ran.",
                    RUN_LIMIT.as_secs() / 60
                ));
            }
        };
        drop(process);
        let text = std::fs::read_to_string(&out);
        let _ = std::fs::remove_file(&out);
        match text {
            Ok(t) => serde_json::from_str(&t).map_err(|e| format!("Deep check output unreadable: {e}")),
            Err(e) => Err(format!("The deep check wrote nothing (exit code {code}): {e}")),
        }
    }
}

/// Windows pages the cards link to. Only these fixed targets can be opened.
pub fn open_page(page: &str) -> Result<(), String> {
    let target = match page {
        "apps" => "ms-settings:appsfeatures",
        "startup" => "ms-settings:startupapps",
        "defender" => "windowsdefender://threat",
        "remote_desktop" => "ms-settings:remotedesktop",
        "proxy" => "ms-settings:network-proxy",
        "network" => "ms-settings:network-status",
        "camera" => "ms-settings:privacy-webcam",
        "microphone" => "ms-settings:privacy-microphone",
        "accounts" => "ms-settings:otherusers",
        "signin" => "ms-settings:signinoptions",
        "certificates" => "certmgr.msc",
        "tasks" => "taskschd.msc",
        "services" => "services.msc",
        _ => return Err(format!("Unknown page {page}")),
    };
    #[cfg(windows)]
    {
        let mut cmd = if target.ends_with(".msc") {
            let mut c = Command::new(system32("mmc.exe"));
            c.arg(target);
            c
        } else {
            let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| "C:\\Windows".into());
            let mut c = Command::new(root.join("explorer.exe"));
            c.arg(target);
            c
        };
        cmd.spawn().map(|_| ()).map_err(|e| format!("Could not open {target}: {e}"))
    }
    #[cfg(not(windows))]
    {
        Err(format!("{target} is a Windows page"))
    }
}

/// Start the watch (hidden, in the tray) when the owner signs in. Written
/// only when the owner switches it on; removed when they switch it off.
pub fn set_start_at_sign_in(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        use winreg::enums::*;
        let run = winreg::RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_READ | KEY_WRITE)
            .map_err(|e| e.to_string())?;
        if enabled {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            run.set_value("PhoneSpyGuard", &format!("\"{}\" --background", exe.display()))
                .map_err(|e| e.to_string())
        } else {
            match run.delete_value("PhoneSpyGuard") {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err("Start at sign-in needs Windows.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_writes_only_its_own_output_files() {
        let dir = std::env::temp_dir();
        assert!(valid_output(&dir.join("psg-deep-1-2.json")));
        assert!(!valid_output(Path::new("psg-deep-1-2.json")));
        assert!(!valid_output(&dir.join("evil.json")));
        assert!(!valid_output(&dir.join("psg-deep-1-2.dll")));
        assert!(!valid_output(&dir.join("missing-dir").join("psg-deep-1-2.json")));
    }

    #[test]
    fn helper_stops_when_cancelled_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("psg-sys-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("psg-deep-7-8.json");
        std::fs::write(cancel_marker(&out), b"").unwrap();
        assert_eq!(run_deep_collect(out.to_str().unwrap()), 2);
        assert!(!out.exists());
        std::fs::remove_file(cancel_marker(&out)).unwrap();
        std::fs::write(&out, b"planted").unwrap();
        assert_eq!(run_deep_collect(out.to_str().unwrap()), 1);
        assert_eq!(std::fs::read(&out).unwrap(), b"planted");
        assert_eq!(run_deep_collect(dir.join("other.json").to_str().unwrap()), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::sync::Mutex;

    // The test binary does not understand --deep-collect, so it exits without
    // writing: this exercises the launch, the phases and the wait.
    #[test]
    fn launches_waits_and_reports_a_missing_result() {
        let phases = Mutex::new(Vec::new());
        let r = deep_collect(None, &AtomicBool::new(false), &|p| phases.lock().unwrap().push(p));
        assert!(r.unwrap_err().contains("wrote nothing"));
        assert_eq!(*phases.lock().unwrap(), vec![DeepPhase::Prompt, DeepPhase::Running]);
    }

    #[test]
    fn cancel_stops_waiting() {
        let r = deep_collect(None, &AtomicBool::new(true), &|_| {});
        assert!(r.unwrap_err().contains("cancelled"));
    }
}
