# Phone Spy Guard for Windows

The desktop app from Phase 2 of the spec: a **Rust core with a Tauri
interface** that checks the owner's own Windows PC for monitoring software,
keyloggers, remote-access tools left behind by scammers, contact with known
stalkerware servers, stalkerware installer files, risky browser extensions,
interception settings and camera/microphone use, and keeps the
same tamper-evident evidence timeline as the phone app. The window has three
tabs, Device check, Evidence and Safety, in the phone app's look (Material 3
colours, Roboto, the same wording and shield icon, and the same plain grey
gear in discreet mode).

It holds the same line as the phone app: it **only reads** the PC it runs on,
asks for administrator rights only for the optional deep check the owner
starts, never installs a driver, never sends the owner's findings, timeline or
answers anywhere (its only network use is downloading signed rule updates,
which the owner can switch off), and has no feature for watching anyone else.

## What is here

| Folder | What it is |
| --- | --- |
| `crates/psg-core` | The Rust twin of the Kotlin `core:detection` and `core:evidence`: facts, signed rule bundles (Ed25519, 2-of-3), the bounded interpreter, the four-level scoring, and the hash-chained signed evidence log. No OS code; builds and tests anywhere. |
| `crates/psg-windows` | Reading Windows (registry, PowerShell for scheduled tasks / Defender / admins / DNS / WMI / Authenticode, browser profile files), turning it into subjects and facts, folding every sighting of a known product into one card, and the 15-minute change watch. Only `collect/registry.rs` and `collect/shell.rs` are Windows-specific; everything else is tested on any OS. |
| `crates/psg-tools` | `psg-sign` (the 3-holder key ceremony, signing, verifying, the public rule log), `psg-verify` (check an exported timeline and any checkpoints, as a police officer or lawyer would), `psg-scan` (run a check from the command line) and `psg-codesign` (Authenticode signing for the release build). |
| `app/` | The Tauri app: `src-tauri/` (window, tray, watch timer, storage, device key) and `ui/` (plain HTML/CSS/JS, no framework, no network; Roboto is bundled under the Apache License 2.0, see `ui/ROBOTO-LICENSE.txt`). |
| `rules/` | `desktop-bundle.json` (version 3, 42 rules; 25 monitoring products, 24 remote-access tools, 25 parental-control and employee-monitoring products, and 131 stalkerware families from Echap with 929 server names, 53 server addresses, 628 sales websites and 3,228 installer hashes), its signatures, the trusted public keys compiled into the app, the public rule log, `update-source.json` (where the app downloads rule updates from) and `KEY-CEREMONY.md`. |
| `conformance/` | Shared fixtures both engines must pass, plus `kotlin/RustConformanceTest.kt` for the Kotlin side. |
| `rules/echap/` | The Echap stalkerware indicator files the bundle's stalkerware list is built from (`ioc.yaml`, `samples.csv`, from commit 426156175adc) and `import_echap.py`, which rebuilds that list. |
| `eval/` | The measured evaluation: 256 common programs and 170 everyday web addresses for false alarms, 75 known-product installs, every Echap family's servers and all 3,228 installer hashes, 15 unknown setups, and Windows' own deep start-up entries. Results in `eval/RESULTS.md`. |

## Build and run on Windows

You need Windows 10 or 11 (64-bit). WebView2, which draws the window, is
already part of Windows 11 and of up-to-date Windows 10.

1. **Install Rust.** Download and run `rustup-init.exe` from
   <https://rustup.rs>. Accept the defaults. If it says the Visual Studio C++
   build tools are missing, let it install them (or install
   "Build Tools for Visual Studio" with the **Desktop development with C++**
   workload), then run `rustup-init.exe` again.
2. **Open PowerShell in this folder**:
   ```powershell
   cd path\to\PhoneSpyGuard\desktop
   ```
3. **Run the tests** (first build downloads libraries and takes a few minutes):
   ```powershell
   cargo test --workspace
   ```
4. **Start the app**:
   ```powershell
   cargo run --release -p phone-spy-guard-desktop
   ```
   Click **Run device check**. "Deep check" shows the Windows administrator
   prompt once.
5. **Check from the command line** (no window), handy for the thesis write-up:
   ```powershell
   cargo run --release -p psg-tools --bin psg-scan          # this PC
   cargo run --release -p psg-tools --bin psg-scan -- --json
   ```
6. **Build the installer** (a per-user installer, so no administrator rights
   are needed to install, NFR-DSK-03):
   ```powershell
   cargo install tauri-cli --version "^2" --locked
   cargo install --path crates\psg-tools --bin psg-codesign --locked
   cd app\src-tauri
   cargo tauri build
   ```
   The installer lands in `target\release\bundle\nsis\`. The build signs
   the app and the installer with Authenticode (NFR-DSK-04) through
   `psg-codesign` when a certificate is configured; see **Release build**
   below.

Closing the window keeps the watch running from the tray icon; use **Quit**
in the tray menu to stop it. The Safety tab has a switch to start the watch
when you sign in.

App data (timeline, baseline, your answers, last report) is in
`%LOCALAPPDATA%\com.phonespyguard.desktop\`, encrypted with DPAPI to your
Windows account. The evidence-signing key and the signed record of the
timeline's length are in Windows Credential Manager under `PhoneSpyGuard`.

## What it checks (FR-DSK)

| Requirement | How |
| --- | --- |
| FR-DSK-01 accounts audit | Every local account: enabled accounts hidden from the sign-in screen (rated Very likely), the built-in Administrator or Guest switched on, automatic sign-in and a stored sign-in password, and administrator accounts besides the owner's. The watch reports an account that appears or is switched on. |
| FR-DSK-02 monitoring software, keyloggers, RATs | Installed programs, running processes, services and start-up entries matched by name (word-start match), Authenticode signer / publisher, and SHA-256 against the signed indicator list in the rule bundle. A match is **Confirmed**. |
| FR-DSK-03 every autostart location | Run / RunOnce / RunServices / RunOnceEx / Policies Run keys and the old `load`/`run` values (HKCU, HKLM, 32-bit, every user in the deep check), start-up folders (shortcuts resolved), automatic services (svchost DLLs resolved), scheduled tasks, WMI event subscriptions (deep check), Image File Execution Options hijacks, Winlogon shell, Userinit, Taskman and per-user or policy shells, and the deeper places Autoruns covers: AppInit_DLLs, AppCertDlls, LSA authentication / notification / security packages, Winlogon Notify and GINA, BootExecute, SilentProcessExit, netsh helpers, Command Processor AutoRun, print monitors, Active Setup, ShellServiceObjectDelayLoad and ShellExecuteHooks, browser helper objects, Remote Desktop start-up programs, and per-user COM class registrations that override the machine's (COM hijacks). Unsigned files loaded into Windows itself are rated Very likely; another publisher's file there, and unsigned add-ins elsewhere, Possible. Also flags unsigned entries in user-writable folders, and new ones since the last check. |
| FR-DSK-04 remote-access tools | 24 tools (AnyDesk, TeamViewer, ScreenConnect, RustDesk, …), plus 25 parental-control and employee-monitoring products (Qustodio, Teramind, ActivTrak, …) rated Possible on the owner's own PC unless the PC is managed by an employer or school. A tool with a service set to start on its own is rated "lets someone in without you"; the card carries removal steps and a prompt to call the bank. |
| FR-DSK-05 browser extensions | Chrome, Edge, Brave, Vivaldi, Opera and Firefox profiles. Flags extensions that can read every site, more strongly if they came from outside the store or are forced on by policy. |
| FR-DSK-06 interception and control | Root certificates added to the user store, proxy and proxy scripts (a certificate plus a proxy is rated together as interception), unusual DNS servers, hosts-file redirects of bank / email / security sites, Remote Desktop, extra administrator accounts, Defender off with no other antivirus, Defender disabled by policy, Defender exclusions (deep check). |
| Stalkerware servers (Echap) | The DNS client cache (names looked up in roughly the last few hours), open TCP connections with the program that owns each, and the hosts file, matched against every Echap stalkerware family's server names (a name and everything under it, never a shared parent such as `firebaseio.com`), server addresses (Cloudflare's shared ranges are dropped at import) and sales websites. A program other than a browser connected to a server is **Confirmed**; a server in the DNS cache or a browser on it (the buyer's dashboard) is Very likely; an address-only match, a sales-site visit or a hosts entry pointing a server somewhere is Possible. Names the hosts file blocks are not counted as contact. |
| Stalkerware installer files (Echap) | `.apk` files in the owner's Downloads, Desktop and Documents (wherever they have been moved), up to 6 folders deep, never following links or junctions and never downloading cloud-only OneDrive files, hashed with SHA-256 against Echap's 3,228 known samples. A match is Very likely: someone downloaded stalkerware to put on a phone. |
| FR-DSK-07 camera and microphone | Windows' CapabilityAccessManager records: which program used which device and when. Unsigned programs, especially from user folders, are flagged, and new use by a flagged program raises a notification. |
| FR-DSK-08 watch | Every 15 minutes while the app is open or in the tray: added / removed / changed items are written to the timeline as CHANGE entries, new findings as FINDING entries, and gaps in the watch as WATCH_GAP entries (telling "PC was off" from "watch was stopped while the PC was on"). |

Each card shows the rules that matched, the plain-language explanation, steps
with buttons that open the right Windows settings page, the raw evidence, and
**I set this up / I didn't do this** buttons. "I set this up" needs Windows
Hello or the account password, is written to the timeline, and covers the
item exactly as it was: if its file, place, publisher or setting changes, the
answer stops counting. It is never offered for a known monitoring product.

## Security review fixes (22 Oct 2026)

| Finding | What changed |
| --- | --- |
| **H6** all three rule keys next to the code; installer trusted them | `dev-keys/` deleted. The three keys are revoked in `psg-core` and the build fails if a trust file names them. The shipped bundle is signed by three single-use keys that were destroyed after signing. `psg-sign` now follows a 3-holder offline ceremony (`rules/KEY-CEREMONY.md`), refuses to write a private key inside the source tree, and keeps a public rule log; the Safety tab shows the bundle's SHA-256 to compare with it. |
| **H5** an innocent explanation cancelled everything; "I set this up" was permanent and anyone could click it | An INNOCENT rule now lists the rule ids it `explains`; only those signals are cancelled (the Kotlin engine is changing to match; the shared fixtures pin it). "I set this up" needs Windows Hello or the password, is tied to the item's fingerprint, and lapses on any change. Turning the watch off also needs confirmation. Parental-control and employee-monitoring products are now a finding on the owner's own PC. |
| **H7** cutting the newest entries went unnoticed; no proof against a rebuilt chain; plaintext files | A signed head (entry count + newest hash) is kept in Credential Manager and checked at every start: cutting or replacing entries is reported and nothing more is appended until the owner keeps the damaged file aside and starts a new timeline whose first entry records the problem. **Checkpoints**: a short signed text the owner emails to themselves or a trusted person; `psg-verify` checks an export against them, which catches truncation or rebuilding even by someone holding the PC's key. Clock moved backwards is reported. All local files are DPAPI-encrypted. |
| **L2** one key under two ids could meet the threshold | Signatures count distinct public keys; trust files with duplicate ids, a duplicated key, or fewer keys than the threshold are refused. |
| **L1** malformed bundles | The Rust parser returns an error for every malformed shape (no panics); the Kotlin fix is in the Android thread. |
| Desktop safety (FR-SAF-02, NFR-SEC-06) | **Quick exit** button and the Esc key hide the window at once and clear the screen. Optional **app lock** (Windows Hello or password before anything is shown). **Discreet mode**, on by default: notifications never name a finding; optionally the window and tray are called "Device Check". |
| **M6** no measured results | `eval/`: 0 of 256 common programs flagged (including NVDA, JAWS, VPNs, antivirus and near-miss names), 75 of 75 known-product installs identified, 10 of 10 unknown stalkerware-style setups caught by behaviour alone, and one documented limit. See `eval/RESULTS.md` for what these numbers do and do not show. |

The signed head deliberately outlives the data folder. If the folder is
deleted (by someone covering their tracks, or by uninstalling with "delete app
data"), the next start reports that the timeline had N entries and now has
none; **Keep it aside and start a new timeline** begins a new one whose first
entry records that.

### What a same-account attacker can still do

Someone who signs in to the same Windows account, or malware that runs as that
account, can read the DPAPI-protected files and the device key, and so can
rebuild a timeline that verifies on its own. The defence is the checkpoint
sent off the PC: a rebuilt or shortened timeline will not contain it. Anyone
who knows the owner's PIN or password can also confirm "I set this up"; every
such answer is written to the timeline. An administrator account can do all
of this and more. The app says so on its Safety tab.

## Shared with the phone app

- **Rule bundles:** same JSON format, same parser rules (including the Kotlin
  parser's quiet coercions), same limits, same Ed25519 2-of-3 / version /
  expiry checks. The desktop bundle adds an `indicators` block, which the
  Kotlin parser ignores, so the format stays one format.
- **Scoring:** the same four levels and the same order of checks.
- **Evidence timeline:** byte-identical canonical content, SHA-256 chain,
  field names and enum spellings, so an export from either app verifies in
  the other.

`conformance/` pins this down. The Rust tests run every fixture; the Kotlin
engine was run against the same fixtures with
`conformance/kotlin/RustConformanceTest.kt` (same verdicts for 17 engine
cases on `scoring-bundle.json` and 26 operator cases, same accept/reject for
25 bundles, same hashes for 4 evidence vectors, verifies a timeline written by
the Rust core, and parses the desktop bundle). The engine and parse cases were
updated for the `explains` change; the Kotlin side passes them once its H5
change lands. To keep that running on the
Kotlin side, copy that file into `core/evidence/src/test/kotlin/` and run
`./gradlew :core:evidence:test` with `PSG_CONFORMANCE_DIR` set to this
`conformance` folder.

## Changing the rules

Edit `rules/desktop-bundle.json` and bump its `version`. To refresh the
stalkerware list from Echap, put their latest `ioc.yaml` and `samples.csv` in
a folder and run `python3 -I rules/echap/import_echap.py <folder>
rules/desktop-bundle.json` (needs PyYAML); it replaces only that list and
prints what it dropped. The Echap data is CC BY 4.0: keep the credit in the
bundle comment and in the app's Safety tab. Releases are signed
by the three key holders, each on their own offline machine, as set out in
`rules/KEY-CEREMONY.md`. Then the builder checks and logs it:

```powershell
cargo run -p psg-tools --bin psg-sign -- verify rules\desktop-bundle.json rules\trusted-keys.json
cargo run -p psg-tools --bin psg-sign -- log rules\desktop-bundle.json rules\rule-log.json
```

## Rule updates (FR-RUL-02)

Installed apps get new rules without a new installer:

- **Automatically**: once a day (first look two minutes after start; an hour
  later after a failure) the app downloads `desktop-bundle.sig.json` and, if
  it changed, `desktop-bundle.json` from the HTTPS folder in
  `rules/update-source.json`. Publishing an update means uploading those two
  files there. Downloads use the certificates Windows trusts, time out after
  30 seconds and stop at 4 MB.
- **From files**: Safety > Detection rules > *Install rules from files…*, for a PC
  whose network may be watched. Choose both files together.

Either way the update is installed only if two of the three trusted keys
signed it, it is newer than every bundle applied before and it has not
expired. It is written atomically to
`%LOCALAPPDATA%\com.phonespyguard.desktop\rules\`, loaded straight away, and
its version, SHA-256 and signers go on the evidence timeline. Anything else is
refused with the reason and the rules in use stay as they were. Turning
automatic updates off needs Windows Hello or the password, because stale
rules miss new spyware.

## Release build

`cargo tauri build` calls `psg-codesign` for the app, every DLL and the
installer. Install it once so the build finds it from any folder:

```powershell
cargo install --path crates\psg-tools --bin psg-codesign --locked
```

It reads the certificate from the environment, never from this folder:

| Variable | Use |
| --- | --- |
| `PSG_SIGN_THUMBPRINT` | A certificate in the Windows store, including one on a hardware token (how OV/EV code-signing certificates are issued now). |
| `PSG_SIGN_PFX`, `PSG_SIGN_PFX_PASSWORD` | A `.pfx` file. |
| `PSG_SIGN_AZURE_DLIB`, `PSG_SIGN_AZURE_METADATA` | Azure Trusted Signing. |
| `PSG_SIGN_TIMESTAMP_URL` | RFC 3161 timestamp server (default DigiCert). |
| `PSG_REQUIRE_SIGNING=1` | Fail the build if no certificate is set. Use it for every build given to users. |

```powershell
$env:PSG_REQUIRE_SIGNING=1; $env:PSG_SIGN_THUMBPRINT="<your certificate's thumbprint>"
cargo build --release -p psg-tools
psg-codesign target\release\psg-scan.exe target\release\psg-verify.exe
cd app\src-tauri; cargo tauri build; cd ..\..
```

Every file is verified (`signtool verify /pa`) right after it is signed. As
the last step, check what you will hand out; this fails if anything is not
validly signed:

```powershell
psg-codesign --verify "target\release\bundle\nsis\Phone Spy Guard_0.4.0_x64-setup.exe" target\release\psg-scan.exe target\release\psg-verify.exe
```

(Tauri signs the copy of the app it packs into the installer and puts the
unsigned build back in `target\release`, so check the installer, not that
file.)
Without a certificate the build still works, prints a warning and leaves the
files unsigned, for development only.

Check an exported timeline (and any checkpoints you sent yourself):

```powershell
cargo run -p psg-tools --bin psg-verify -- PhoneSpyGuard-timeline-....json checkpoint1.txt
```

Measure detection and false alarms again after changing rules:

```powershell
$env:PSG_WRITE_EVAL=1; cargo test -p psg-windows --test evaluation
```

## Before the first public release: what needs you

The code for each of these is done and tested; each needs something only the
project owner can provide.

- **Three rule-key holders.** Until they run the ceremony in
  `rules/KEY-CEREMONY.md`, the shipped rules are signed by single-use keys
  that no longer exist, so no update can be signed for this build.
- **Where updates are published.** Put an HTTPS folder URL in
  `rules/update-source.json` (for example a GitHub Releases download URL).
  Until then automatic updates are off and the Safety tab says so; installing from
  files works.
- **A code-signing certificate**, set as above. Until then SmartScreen warns
  on install.

## Not in this release

- **Real-device evaluation**: `eval/` measures matching and scoring on
  synthetic inventories; running real stalkerware samples in a lab VM is
  still to do.
- **Hardware-backed device key** (TPM): Windows' TPM provider signs with
  ECDSA P-256, not the Ed25519 the phone and desktop timelines share, so
  this needs a new evidence format version on all three platforms. Today
  the key is protected by DPAPI and checkpoints are the defence.
- **Windows program hashes**: stalkerware installer hashes come from
  Echap, but the monitoring and remote-access lists still match Windows
  programs by name, publisher and signer only; their `sha256` lists are
  empty until an open feed of Windows samples is chosen.
- **Checking a phone from the PC** (USB, Android debugging or an iPhone
  backup) and an optional hash-reputation lookup are not in this release.
- **macOS** (FR-DSK-09), **phone–PC linking** (FR-DSK-10) and Linux
  (FR-DSK-11).
- Timing and memory budgets (NFR-DSK-01/02) need measuring on a real
  4 GB laptop.
