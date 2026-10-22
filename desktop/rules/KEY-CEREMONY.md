# Rule-signing keys

The apps only accept a rule bundle that has valid signatures from 2 of 3 trusted Ed25519 keys (NFR-SEC-15). That check protects users only if the three private keys are held by **three different people, each on their own offline machine**. If one person has all three, one stolen laptop is enough to push rules that switch detection off. That is what happened in development: all three private keys were sitting in `desktop/dev-keys/` (security review, finding H6).

## What this build does

- The old development keys (`release-1`, `release-2` and `release-3`) are deleted and **revoked in code**. `psg_core::verifier::REVOKED_KEYS` lists their public halves. Every trust file that contains one of them is refused, and the app's `build.rs` fails the build if `rules/trusted-keys.json` still names one. No build can ever trust those keys again.
- `rules/desktop-bundle.json` was signed with `psg-sign sign-once`. That command:
  1. makes three keys in memory,
  2. signs the bundle with all three,
  3. writes their public halves to `rules/trusted-keys.json`,
  4. drops the private keys without ever writing them to disk.

  As a result, **nobody can sign further rules for keys this build trusts**, including us. Nothing stolen from a developer's laptop can push rules to installed apps. To publish rule updates to installed apps, run the ceremony below once, commit the new `trusted-keys.json`, and ship one more build. From then on, updates go out without new builds.
- `rules/rule-log.json` is the public log of every bundle released (NFR-SEC-18). The app shows the SHA-256 fingerprint of the bundle it verified under Settings > Rules. Anyone can compare it with the log.

## The ceremony for a real release

You need three key holders, for example the developer, the thesis supervisor and a partner organisation's technical lead. Each holder works on a machine that is offline while their key is in use, and keeps the private key on removable media in a safe place.

1. **Each holder** makes their key:

   ```
   psg-sign keygen release-<name> E:\psg-key
   ```

   This writes `release-<name>.key.json`, the private key, which never leaves that drive. It also writes `release-<name>.pub.json`, which the holder sends to the builder. `keygen` refuses to write inside the source tree.

2. **The builder** makes the trust file from the three public files and commits it:

   ```
   psg-sign trust 2 release-a.pub.json release-b.pub.json release-c.pub.json > rules\trusted-keys.json
   ```

   This step refuses duplicate ids, the same key listed twice, a threshold below 2, and the revoked development keys.

3. **For each rule release**, the bundle and its `.sig.json` travel to two of the holders. Each holder reviews the diff, then adds their signature on their own machine:

   ```
   psg-sign sign rules\desktop-bundle.json E:\psg-key\release-<name>.key.json
   ```

   Signatures are merged into `desktop-bundle.sig.json`. Re-signing replaces only that holder's own signature.

4. **The builder** verifies the bundle and appends it to the public log:

   ```
   psg-sign verify rules\desktop-bundle.json rules\trusted-keys.json
   psg-sign log rules\desktop-bundle.json rules\rule-log.json
   ```

   Then the builder publishes the log entry somewhere the team cannot quietly rewrite, such as the thesis appendix or a public repository.

5. **If a key is lost or a holder leaves**, add the key's public half to `REVOKED_KEYS`, run the ceremony for a replacement, and ship a new build.

## Publishing an update

After step 4, upload `desktop-bundle.json` and `desktop-bundle.sig.json` to the HTTPS folder named in `rules/update-source.json`. Installed apps download them within a day. Owners can also install the two files by hand under Settings > Rules.

An installed app uses an update only if all of these hold:

- the 2-of-3 signature check passes against the keys compiled into it,
- its version is newer than every bundle applied before,
- it has not expired.

The update server is not trusted for anything: whoever controls it can only withhold updates, not change rules. If an update fails any check, it is refused with the reason and the app keeps the rules it has.
