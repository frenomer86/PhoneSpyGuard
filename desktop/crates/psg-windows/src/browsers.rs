//! Browser extensions (FR-DSK-05). Reads profile folders directly, so it is
//! plain file parsing and runs (and is tested) on any platform.
//!
//! Chromium browsers (Chrome, Edge, Brave): each profile's `Secure
//! Preferences` / `Preferences` lists extensions with their install location,
//! and `Extensions/<id>/<version>/manifest.json` has the permissions.
//! Firefox: each profile's `extensions.json` has both.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// One extension, browser-neutral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionInfo {
    pub browser: String,
    pub profile: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub all_sites: bool,
    pub outside_store: bool,
    pub force_installed: bool,
    pub enabled: bool,
    pub permissions: Vec<String>,
}

/// Host patterns that mean "every website".
pub fn is_all_sites_pattern(p: &str) -> bool {
    if p == "<all_urls>" {
        return true;
    }
    // scheme://host/path with host exactly "*".
    match p.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.split('/').next().unwrap_or("");
            matches!(scheme, "*" | "http" | "https") && host == "*"
        }
        None => false,
    }
}

/// Chromium `location` values (extensions/common/mojom/manifest.mojom).
const LOC_INTERNAL: i64 = 1;
const LOC_UNPACKED: i64 = 4;
const LOC_COMPONENT: i64 = 5;
const LOC_EXTERNAL_POLICY_DOWNLOAD: i64 = 7;
const LOC_COMMAND_LINE: i64 = 8;
const LOC_EXTERNAL_POLICY: i64 = 9;
const LOC_EXTERNAL_COMPONENT: i64 = 10;

/// All extensions in every profile of one Chromium browser.
/// `user_data` is e.g. `%LOCALAPPDATA%\Google\Chrome\User Data`.
pub fn chromium_extensions(browser: &str, user_data: &Path) -> Vec<ExtensionInfo> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(user_data) else { return out };
    let mut profiles: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("Extensions").is_dir() || p.join("Preferences").is_file())
        .collect();
    profiles.sort();
    for profile in profiles {
        out.extend(chromium_profile(browser, &profile));
    }
    out
}

fn read_json(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

fn chromium_profile(browser: &str, profile: &Path) -> Vec<ExtensionInfo> {
    let profile_name = profile.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();

    // Settings for each extension id, from both preference files.
    let mut settings = serde_json::Map::new();
    for file in ["Preferences", "Secure Preferences"] {
        if let Some(Value::Object(map)) =
            read_json(&profile.join(file)).and_then(|v| v.pointer("/extensions/settings").cloned())
        {
            for (id, s) in map {
                settings.entry(id).or_insert(s);
            }
        }
    }

    let mut ids: BTreeSet<String> = settings.keys().cloned().collect();
    if let Ok(dirs) = fs::read_dir(profile.join("Extensions")) {
        ids.extend(dirs.flatten().filter(|d| d.path().is_dir()).map(|d| d.file_name().to_string_lossy().into_owned()));
    }

    let mut out = Vec::new();
    for id in ids {
        let s = settings.get(&id).cloned().unwrap_or(Value::Null);
        let location = s.get("location").and_then(Value::as_i64);
        if matches!(location, Some(LOC_COMPONENT) | Some(LOC_EXTERNAL_COMPONENT)) {
            continue; // built into the browser
        }

        // The manifest: from the newest version folder, or (unpacked) from
        // the path the settings name, or embedded in old settings.
        let ext_root = newest_version_dir(&profile.join("Extensions").join(&id)).or_else(|| {
            s.get("path")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .filter(|p| p.join("manifest.json").is_file())
        });
        let manifest = ext_root
            .as_deref()
            .and_then(|root| read_json(&root.join("manifest.json")))
            .or_else(|| s.get("manifest").cloned());
        let Some(manifest) = manifest.filter(Value::is_object) else {
            continue;
        };
        let name = resolve_name(&manifest, ext_root.as_deref()).unwrap_or_else(|| id.clone());
        let version = manifest.get("version").and_then(Value::as_str).unwrap_or("").to_string();

        let permissions = chromium_permissions(&manifest);
        let all_sites = permissions.iter().any(|p| is_all_sites_pattern(p));
        let from_webstore = s.get("from_webstore").and_then(Value::as_bool).unwrap_or(false);
        let force_installed =
            matches!(location, Some(LOC_EXTERNAL_POLICY_DOWNLOAD) | Some(LOC_EXTERNAL_POLICY));
        let outside_store = matches!(location, Some(LOC_UNPACKED) | Some(LOC_COMMAND_LINE))
            || (!from_webstore && !force_installed && location != Some(LOC_INTERNAL) && location.is_some());
        // state 0 = disabled in older builds; disable_reasons non-empty in newer.
        let enabled = s.get("state").and_then(Value::as_i64) != Some(0)
            && s.get("disable_reasons").is_none_or(|d| match d {
                Value::Array(a) => a.is_empty(),
                Value::Number(n) => n.as_i64() == Some(0),
                _ => true,
            });

        out.push(ExtensionInfo {
            browser: browser.to_string(),
            profile: profile_name.clone(),
            id,
            name,
            version,
            all_sites,
            outside_store,
            force_installed,
            enabled,
            permissions,
        });
    }
    out
}

fn newest_version_dir(ext_dir: &Path) -> Option<PathBuf> {
    let mut versions: Vec<PathBuf> = fs::read_dir(ext_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("manifest.json").is_file())
        .collect();
    versions.sort();
    versions.pop()
}

/// Every permission and host pattern the manifest asks for.
fn chromium_permissions(manifest: &Value) -> Vec<String> {
    let mut perms = BTreeSet::new();
    for key in ["permissions", "host_permissions", "optional_host_permissions"] {
        if let Some(Value::Array(a)) = manifest.get(key) {
            perms.extend(a.iter().filter_map(Value::as_str).map(str::to_string));
        }
    }
    if let Some(Value::Array(scripts)) = manifest.get("content_scripts") {
        for s in scripts {
            if let Some(Value::Array(m)) = s.get("matches") {
                perms.extend(m.iter().filter_map(Value::as_str).map(str::to_string));
            }
        }
    }
    perms.into_iter().collect()
}

/// Resolve `__MSG_name__` names from `_locales/<default_locale>/messages.json`.
fn resolve_name(manifest: &Value, root: Option<&Path>) -> Option<String> {
    let raw = manifest.get("name").and_then(Value::as_str)?;
    let Some(key) = raw.strip_prefix("__MSG_").and_then(|r| r.strip_suffix("__")) else {
        return Some(raw.to_string());
    };
    let root = root?;
    let locale = manifest.get("default_locale").and_then(Value::as_str).unwrap_or("en");
    let messages = read_json(&root.join("_locales").join(locale).join("messages.json"))?;
    let obj = messages.as_object()?;
    obj.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .and_then(|(_, v)| v.get("message"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| Some(raw.to_string()))
}

/// All extensions in every Firefox profile under `profiles_dir`
/// (`%APPDATA%\Mozilla\Firefox\Profiles`).
pub fn firefox_extensions(profiles_dir: &Path) -> Vec<ExtensionInfo> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(profiles_dir) else { return out };
    let mut profiles: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    profiles.sort();
    for profile in profiles {
        let Some(doc) = read_json(&profile.join("extensions.json")) else { continue };
        let profile_name =
            profile.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(Value::Array(addons)) = doc.get("addons") else { continue };
        for a in addons {
            if a.get("type").and_then(Value::as_str) != Some("extension") {
                continue;
            }
            let location = a.get("location").and_then(Value::as_str).unwrap_or("");
            if matches!(location, "app-builtin" | "app-system-defaults" | "app-system-addons") {
                continue;
            }
            let mut perms: BTreeSet<String> = BTreeSet::new();
            for key in ["userPermissions", "optionalPermissions"] {
                for sub in ["origins", "permissions"] {
                    if let Some(Value::Array(v)) = a.get(key).and_then(|p| p.get(sub)) {
                        perms.extend(v.iter().filter_map(Value::as_str).map(str::to_string));
                    }
                }
            }
            let source = a
                .pointer("/installTelemetryInfo/source")
                .and_then(Value::as_str)
                .unwrap_or("");
            let signed_state = a.get("signedState").and_then(Value::as_i64).unwrap_or(0);
            let foreign = a.get("foreignInstall").and_then(Value::as_bool).unwrap_or(false);
            let force_installed = source == "enterprise-policy";
            let outside_store =
                !force_installed && (foreign || signed_state < 2 || location == "app-global");
            out.push(ExtensionInfo {
                browser: "Firefox".into(),
                profile: profile_name.clone(),
                id: a.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
                name: a
                    .pointer("/defaultLocale/name")
                    .and_then(Value::as_str)
                    .unwrap_or("(unnamed)")
                    .to_string(),
                version: a.get("version").and_then(Value::as_str).unwrap_or("").to_string(),
                all_sites: perms.iter().any(|p| is_all_sites_pattern(p)),
                outside_store,
                force_installed,
                enabled: a.get("active").and_then(Value::as_bool).unwrap_or(true),
                permissions: perms.into_iter().collect(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn all_sites_patterns() {
        for p in ["<all_urls>", "*://*/*", "https://*/*", "http://*/"] {
            assert!(is_all_sites_pattern(p), "{p}");
        }
        for p in ["https://*.google.com/*", "storage", "*://mail.example.com/*"] {
            assert!(!is_all_sites_pattern(p), "{p}");
        }
    }

    #[test]
    fn reads_chromium_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let ud = dir.path();
        write(
            &ud.join("Default/Secure Preferences"),
            r#"{"extensions":{"settings":{
                "storeext":{"location":1,"from_webstore":true},
                "devext":{"location":4,"path":"PLACEHOLDER"},
                "polext":{"location":7},
                "builtin":{"location":5}
            }}}"#,
        );
        write(
            &ud.join("Default/Extensions/storeext/1.2_0/manifest.json"),
            r#"{"name":"__MSG_appName__","default_locale":"en","version":"1.2","host_permissions":["<all_urls>"]}"#,
        );
        write(
            &ud.join("Default/Extensions/storeext/1.2_0/_locales/en/messages.json"),
            r#"{"appName":{"message":"Grammar Helper"}}"#,
        );
        write(
            &ud.join("Default/Extensions/polext/3.0_0/manifest.json"),
            r#"{"name":"Corp Policy","version":"3.0","content_scripts":[{"matches":["https://*/*"]}]}"#,
        );
        // Unpacked extension lives outside the profile.
        let unpacked = ud.join("elsewhere/spyext");
        write(
            &unpacked.join("manifest.json"),
            r#"{"name":"Helper","version":"0.1","permissions":["tabs","*://*/*"]}"#,
        );
        let prefs = fs::read_to_string(ud.join("Default/Secure Preferences")).unwrap().replace(
            "PLACEHOLDER",
            &unpacked.to_string_lossy().replace('\\', "\\\\"),
        );
        fs::write(ud.join("Default/Secure Preferences"), prefs).unwrap();

        let mut exts = chromium_extensions("Chrome", ud);
        exts.sort_by(|a, b| a.id.cmp(&b.id));
        let ids: Vec<&str> = exts.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["devext", "polext", "storeext"]);

        let dev = &exts[0];
        assert!(dev.all_sites && dev.outside_store && !dev.force_installed);
        assert_eq!(dev.name, "Helper");
        let pol = &exts[1];
        assert!(pol.all_sites && pol.force_installed && !pol.outside_store);
        let store = &exts[2];
        assert_eq!(store.name, "Grammar Helper");
        assert!(store.all_sites && !store.outside_store && !store.force_installed);
    }

    #[test]
    fn reads_firefox_profiles() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("abc.default-release/extensions.json"),
            r#"{"addons":[
              {"id":"ublock@raymondhill.net","type":"extension","location":"app-profile","signedState":2,
               "defaultLocale":{"name":"uBlock Origin"},"version":"1.60","active":true,
               "userPermissions":{"permissions":["storage"],"origins":["<all_urls>"]}},
              {"id":"evil@x","type":"extension","location":"app-profile","signedState":0,"foreignInstall":true,
               "defaultLocale":{"name":"Updater"},"userPermissions":{"origins":["*://*/*"]}},
              {"id":"theme@x","type":"theme","location":"app-profile"},
              {"id":"screenshots@mozilla.org","type":"extension","location":"app-builtin"}
            ]}"#,
        );
        let exts = firefox_extensions(dir.path());
        assert_eq!(exts.len(), 2);
        assert!(exts[0].all_sites && !exts[0].outside_store);
        assert!(exts[1].all_sites && exts[1].outside_store);
        assert_eq!(exts[1].name, "Updater");
    }
}
