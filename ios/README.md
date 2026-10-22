# Phone Spy Guard — iPhone companion

The iPhone part of Phone Spy Guard. It does one job: check this iPhone for
signs of spyware, show what to do safely, and keep signed proof. iOS does
not let one app look inside another, so it checks what an iPhone app *can*
see, and says plainly what it cannot:

| Spec | What the app does |
|---|---|
| FR-IOS-02 device checks | Reads whether a passcode is set, the iOS version against the newest known release, the system proxy, sandbox-visible jailbreak traces and an attached debugger (NFR-SEC-03). Guides the owner through Safety Check, Lockdown Mode, the configuration-profile check and Apple threat notifications. |
| FR-IOS-03 diagnostic archive | The owner shares a sysdiagnose (`.tar.gz`) into the app. It is read **on the phone** in one streaming pass (a plain-Swift gzip + tar reader: 206 MB in 2.6 s on a laptop core) and its `shutdown.log`, the running-process list (`ps.txt`) and crash-report names are checked for published indicators (83 process names, 49 paths, 15 file names and 4,980 domains from the 18 STIX2 sets MVT lists: Pegasus, Predator, KingSpawn, Operation Triangulation and others) and with Kaspersky's "sticky process" method. The owner can share in a newer STIX2 file. It checks for *published* indicators: new or changed spyware will not match. |
| FR-IOS-04 MVT hand-off | Step-by-step guide to Amnesty's MVT on a computer without the desktop app. |
| FR-EVD-01..03 evidence | Same hash-chained timeline as Android and desktop, signed with a non-exportable **Secure Enclave** P-256 key (ECDSA-SHA256, DER, the same scheme as the Android Keystore key). A signed head (entry count + last hash) is kept in the Keychain, so deleting the newest entries shows as a broken timeline, and the owner can send a checkpoint off the phone that proves it to anyone. Exports JSON (public key, head and, when the build has the capability, an Apple App Attest attestation) and PDF, with a warning if the chain is broken. |
| FR-SAF-01..05 safety | Safety guidance before every "remove" step, helplines for the owner's country (including Ghana: Orange Support Centre 0800 111 222, police 191), quick exit, a neutral cover in the app switcher, an optional Face ID / passcode app lock, a plain alternate icon and how to keep the app off the Home Screen. |

## Same look as the Android app

Tabs: Device check, Safety and Evidence. The tint is the Android app's
purple (#6750A4, #D0BCFF in dark mode), and the icon is Android's white
shield with a tick on #0B3D5C, with its grey gear as the discreet icon.
Device results use Android's words: "Confirmed spying", "Very likely
spying", "Possible — worth a look". A check with any step unanswered is
"Incomplete", never clear. The app has no demo mode and no sample data.

## One engine, three apps

`Sources/PSGCore` is the Swift twin of the Kotlin `core:detection` +
`core:evidence` and the Rust `psg-core`: the same rule-bundle format and
limits, bounded interpreter, four-level scoring and evidence hashing. It is
pinned by the shared fixtures in `../desktop/conformance/` — the Swift tests
read them straight from there, so **keep `ios/` next to `desktop/`**.

The iPhone rules are `Sources/PSGCompanion/Resources/ios-bundle.json`
(16 rules in the shared format, plus an `ios` data block that the Kotlin
and Rust parsers ignore). Innocent rules use the shared `explains`
list, so a work profile can excuse the proxy it set and nothing else. The
indicators are a second signed file, `ios-indicators.json`, built by
`tools/build_indicators.py` from the STIX2 files MVT lists.

**Updates (FR-RUL-02).** The app checks once a day (and on request under
Safety > About these checks) for newer signed copies of both files at
the build's `PSG_RULES_BASE_URL`. Everything is downloaded to a staging
folder and loaded exactly as the app will load it; a file is kept only if
it carries 2-of-3 signatures from the keys in the app and a higher version
than the one in use. A tampered, under-signed, older or half-downloaded set
changes nothing, and a valid update keeps the app working after the built-in
rules expire. The request carries no identifier or cookie. The same screen
shows each file's version, origin and SHA-256 for comparison with the public
rule log (`psg-ios-check log`).

**Signing.** The old development keys are revoked: every engine refuses
them. Two ways to sign:

- *Build signing* (what is in the folder now): `sign-once` makes three keys
  in memory, signs both files 2-of-3 and destroys the keys, so nobody
  holds a key the app trusts, but nobody can sign an update for that build
  either. Re-sign both together after any edit:

  ```
  swift run psg-ios-check sign-once Sources/PSGCompanion/Resources/ios-bundle.json \
    Sources/PSGCompanion/Resources/ios-indicators.json
  ```

- *Release signing* (needed before the App Store, and the release workflow
  refuses to run without it): three key holders each run, on their own
  offline machine (`../desktop/rules/KEY-CEREMONY.md`),

  ```
  psg-ios-check keygen <their-id> <usb-folder>          # refuses to write inside the source tree
  psg-ios-check trust 2 a.pub.json b.pub.json c.pub.json > Sources/PSGCompanion/Resources/trusted-keys.json
  psg-ios-check sign <file.json> <their-id>.key.json    # each holder adds a signature; 2 of 3 needed
  psg-ios-check log Sources/PSGCompanion/Resources rule-log.json   # public record of what was signed
  ```

  The signed files are then published at
  `PSG_RULES_BASE_URL`, and later updates are signed the same way.

 Keys marked
`"development": true` in the trust file are refused by release builds; only
Debug builds, or builds with the `PSG_ALLOW_DEV_KEYS` flag, accept them, and
those show a red "Development build" banner.

## Layout

```
ios/
  Package.swift               Swift package: PSGCore, PSGCompanion, psg-ios-check
  Sources/PSGCore/            rules, scoring, verifier, evidence log, JSON
  Sources/PSGCompanion/       device check, safety guidance, helplines, signed updates,
                              Archive/ (gzip + tar), Diagnostics/ (shutdown.log, ps.txt, STIX2)
    Resources/                ios-bundle(.sig).json, ios-indicators(.sig).json,
                              trusted-keys.json, helplines.json
  Sources/psg-ios-check/      command-line tool: analyze, verify-evidence, and the signing
                              commands (keygen, trust, sign, log, sign-once, verify)
  Tests/                      52 tests (see below)
  tools/make_fixtures.py      regenerates the test archives
  tools/build_indicators.py   builds ios-indicators.json from MVT's STIX2 files
  EVALUATION.md               what has been measured and what has not
  App/                        the SwiftUI iPhone app (needs Xcode)
    project.yml               XcodeGen project spec
    Sources/                  app, views, Secure Enclave signer, device readers, PDF export,
                              rule updates (Platform/RuleUpdates.swift)
    Resources/                app icon, privacy manifest
```

## What runs where

**On Windows, Linux or a Mac (no Xcode needed):** the whole logic layer.
Install Swift from https://www.swift.org/install/windows/ (or use the
`swift:6.0` Docker image), then in `ios/`:

```
swift test                                   # 52 tests
swift run psg-ios-check analyze sysdiagnose_….tar.gz [--stix pegasus.stix2]
swift run psg-ios-check verify-evidence evidence-timeline.json --checkpoint checkpoint.txt
```

`verify-evidence` also checks the desktop's and (once it exports the public
key) Android's timelines.

**Needs a Mac with Xcode 15 or later:** building the app in `App/`.

```
brew install xcodegen
cd ios/App && xcodegen generate && open PhoneSpyGuard.xcodeproj
```

Pick your Apple ID team under Signing & Capabilities and run it on an
iPhone (iOS 16 or later). A free Apple ID works for your own phone; the app
then has to be re-installed every 7 days. App Store distribution needs the
paid Apple Developer Program.

**No Mac? Two routes:**

1. *GitHub Actions (free).* The repository's `.github/workflows/ios.yml`
   runs on every push to `ios/`: it runs the tests and builds the app on a macOS runner, and produces
   an unsigned `.ipa`. On Windows, Sideloadly or AltStore can sign that with
   a free Apple ID and install it on your iPhone over USB.
2. *A rented Mac in the cloud* (MacinCloud and similar) by the hour.

## Status (2026-10-22)

**Verified here** (Linux, Swift 6.0.3):

- 52 tests pass: all shared conformance fixtures (engine verdicts with
  `explains`, operators, parse limits, evidence hash vectors, the
  desktop-signed timeline and rule bundle), the companion checks, the signed
  head and checkpoints, trust-file rules, signed updates (newer accepted;
  tampered, one-signature, rolled-back, plain-HTTP and partial downloads
  refused; recovery after the built-in rules expire), "incomplete, never
  clear" for unanswered steps, `ps.txt` parsing, and the archive reader on synthetic sysdiagnoses.
- The key ceremony commands were run end to end (keygen, trust, sign,
  verify), and `keygen` refuses to write into the source tree.
- `.github/workflows/ios.yml` passes actionlint.

**Not verified yet, because it needs a Mac or a real iPhone:**

- The app (`App/`) is syntax-checked only. They have
  not been compiled against the iOS SDK. The first macOS CI run is that
  compile; expect a few fixes there.
- Nothing has run on an iPhone: Secure Enclave signing, App Attest, Face ID
  lock, the alternate icon and the device posture readers.
- The signed App Store job has never run: it needs the release keys from
  the ceremony, an Apple Developer account and the secrets listed in the
  workflow.
- `PSG_RULES_BASE_URL` is empty until someone publishes the signed files on
  an HTTPS host, so builds use only their built-in rules until then.
- iOS release numbers in the bundle were refreshed from Apple's security
  releases page on 2026-10-22 (newest: 27.0.1, 26.7.1, 18.7.10, 17.7.2,
  16.7.16). Refresh them with every rule release.

## Security review fixes (iPhone part)

| Finding | What changed |
|---|---|
| H5 innocent answers excuse everything | Innocent rules name what they explain (`explains`); an owner-made jailbreak is still a risk; the proxy is its own subject. |
| H6 dev keys trusted | Old keys revoked in every engine; files re-signed with single-use keys; release builds refuse keys marked development. |
| H7 truncation, device proof | Signed head in the Keychain and in exports; off-device checkpoints; App Attest attestation when the capability is on. |
| L2 one key, two ids | Trust files with duplicate ids or keys, or fewer keys than the threshold, are refused; signatures count distinct keys. |
| M1 thin indicators | 18 published STIX2 sets shipped as a signed file; wording is "checks for published indicators". |
| M6 no measurements | `EVALUATION.md` says what is measured and what is not. |
| FR-SAF-05 / NFR-SEC-06 | App lock and plain alternate icon. iOS cannot rename an installed app; the name is a build setting (`PSG_DISPLAY_NAME`). |
