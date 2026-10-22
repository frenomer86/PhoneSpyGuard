# Phone Spy Guard

Phone Spy Guard checks **your own** phone or PC for stalkerware and spyware,
explains in plain language what it found and what to do safely, and keeps a
**tamper‑evident evidence timeline** you can hand to the police, a lawyer or a
support worker.

It does one job and is built to be trusted with it:

- **Detect.** Known stalkerware is matched by package name **or** signing
  certificate (614 package names and 473 certificate fingerprints across about
  149 families from the public Echap `stalkerware-indicators` dataset, plus
  mercenary‑spyware indicators from Amnesty's MVT project), so a renamed copy
  signed by the same key is still caught. Unknown tools are caught by
  behaviour: hidden apps holding accessibility, device‑admin, notification or
  SMS powers, sideloaded installs, and new powers that appear between checks.
- **Explain.** Every finding has one of four confidence levels (*Confirmed*,
  *Very likely*, *Possible*, *Unlikely*), checks for an innocent explanation
  (a parental‑control app, a screen reader, a work profile) before accusing,
  and leads with safety advice: removing spyware can alert the person who
  installed it, so save the evidence and make a plan first.
- **Keep evidence.** An append‑only, hash‑chained log signed by a
  hardware‑backed key (Android Keystore, Apple Secure Enclave, a per‑device key
  on Windows). Any edit, deletion or reordering breaks verification, and an
  export can be checked off the device by anyone.

By design the apps hold **none** of the powers stalkerware abuses (no
accessibility, device‑admin, SMS, microphone, camera, location or notification
access) and have **no feature that lets anyone watch another person**.
Detection runs entirely on the device. The only network traffic is downloading
signed rule updates, which the owner can switch off.

## Platforms

| Folder | Platform | Language |
| --- | --- | --- |
| `app/` + `core/` | Android 9+ | Kotlin, Jetpack Compose |
| `desktop/` | Windows 10/11 | Rust core, Tauri interface |
| `ios/` | iPhone companion | Swift |

All three share one rule‑bundle format, one bounded rule interpreter, one
scoring specification and one evidence format. The shared fixtures in
`desktop/conformance/` prove that the Kotlin, Rust and Swift engines score and
log identically.

## How detection rules are trusted

- **Rules are data, never code.** A rule can only describe a predicate over
  device facts (`all` / `any` / `not` and leaf comparisons). The parser rejects
  anything outside the known shapes or beyond its size and depth limits, and
  the interpreter enforces a time budget, so a bad bundle can't hang a scan.
- **Signed 2‑of‑3, no rollback.** A rule update is accepted only with valid
  Ed25519 signatures from two of three independent key holders, and never if it
  is older than the installed bundle or expired. See
  [`desktop/rules/KEY-CEREMONY.md`](desktop/rules/KEY-CEREMONY.md).
- **Honest results.** A rule that can't be evaluated is reported as skipped,
  never silently dropped, and a check with unanswered steps is *Incomplete*,
  never "clear".

## Core modules (Kotlin)

| Module | What it is |
| --- | --- |
| `core:detection` | Device facts, signed rule bundles, the bounded interpreter, four‑level scoring, signed rule updates. No Android dependencies, so it tests on any JVM. |
| `core:evidence` | The hash‑chained, signed evidence timeline, signed checkpoints, portable export and off‑device verification, and Keystore attestation‑chain checks. |
| `core:watch` | The change watcher: what gained a surveillance power, hid its icon or was sideloaded since the last check, and any gap when the watch itself was stopped. |
| `core:safety` | Safety‑planning guidance and verified support resources shown before any removal step. |
| `core:eval` | Detection evaluation over an independent app set (known stalkerware caught, no high‑risk false alarm on real Play apps). |
| `core:conformance` | Runs the shared cross‑engine fixtures in `desktop/conformance/`. |

The modules `core:accounts`, `core:scam` and `core:phone` (account checkup,
message check and phone‑number guard) are being retired so the apps stay
focused on spyware detection.

## Build and test

**Android core and app** (JDK 21; the Gradle wrapper is included):

```bash
./gradlew test        # all core unit tests, no Android SDK needed
```

The `:app` module is included only when an Android SDK is present
(`ANDROID_HOME`, `ANDROID_SDK_ROOT` or a `local.properties`). Open the project
in Android Studio to build and run the app on Android 9 or newer.

**Windows desktop** (Rust): see [`desktop/README.md`](desktop/README.md).

```powershell
cd desktop
cargo test --workspace
cargo run --release -p phone-spy-guard-desktop
```

**iPhone companion** (Swift): see [`ios/README.md`](ios/README.md).

```bash
cd ios
swift test
```

GitHub Actions runs the Kotlin core tests and the iOS tests and builds on every
push (`.github/workflows/`).

## Limits

No app can promise a phone is clean. Detection matches published indicators
and known behaviours; brand‑new or targeted spyware may not match. On iPhone,
iOS does not let one app look inside another, so the companion checks what an
iPhone app can see and says plainly what it cannot. If you are in danger,
contact local emergency services or a domestic‑abuse helpline from a device the
other person has never had access to.

## Reporting a security issue

Please report vulnerabilities privately through GitHub's
**Security → Report a vulnerability** on this repository rather than in a
public issue.

## License

See [LICENSE](LICENSE). Roboto, bundled with the desktop app, is under the
Apache License 2.0 (`desktop/app/ui/ROBOTO-LICENSE.txt`).
