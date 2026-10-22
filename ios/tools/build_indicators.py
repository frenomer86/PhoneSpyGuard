#!/usr/bin/env python3
"""Build Sources/PSGCompanion/Resources/ios-indicators.json from the STIX2
files that Amnesty's MVT lists (mvt-project/mvt-indicators, indicators.yaml).

Usage: build_indicators.py <dir with downloaded .stix2 files> <out.json> <version>

Keeps the same pattern types IndicatorSet.fromSTIX2 reads in the app:
process:name, file:name, file:path, domain-name:value and url:value hosts.
Sign the output with `psg-ios-check sign` before shipping it.
"""
import datetime, json, os, re, sys
from urllib.parse import urlparse

COMPARISON = re.compile(r"([a-z0-9-]+):([a-z0-9_.]+)\s*=\s*'((?:\\'|[^'])*)'", re.I)
# Android-only stalkerware app list: package names the iPhone cannot use.
SKIP = {"generated__stalkerware.stix2"}

def read(path):
    objs = json.load(open(path, encoding="utf-8"))["objects"]
    out = {"processNames": set(), "fileNames": set(), "pathPrefixes": set(), "domains": set()}
    for o in objs:
        if o.get("type") != "indicator" or "pattern" not in o:
            continue
        for obj, prop, val in COMPARISON.findall(o["pattern"]):
            obj, prop, val = obj.lower(), prop.lower(), val.replace("\\'", "'")
            if (obj, prop) == ("process", "name"): out["processNames"].add(val)
            elif (obj, prop) == ("file", "name"): out["fileNames"].add(val)
            elif (obj, prop) in (("file", "path"), ("directory", "path")): out["pathPrefixes"].add(val)
            elif (obj, prop) == ("domain-name", "value"): out["domains"].add(val.lower().rstrip("."))
            elif (obj, prop) == ("url", "value"):
                host = urlparse(val).hostname
                if host: out["domains"].add(host.lower())
    name = next((o.get("name") for o in objs if o.get("type") == "malware"), None)
    return name, out

def main(src, dst, version):
    total = {"processNames": set(), "fileNames": set(), "pathPrefixes": set(), "domains": set()}
    sets = []
    for fn in sorted(os.listdir(src)):
        if not fn.endswith(".stix2") or fn in SKIP:
            continue
        name, got = read(os.path.join(src, fn))
        counts = {k: len(v) for k, v in got.items()}
        sets.append({"file": fn.replace("__", "/"), "malware": name or fn, "counts": counts})
        for k in total: total[k] |= got[k]
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    doc = {
        "format": "phone-spy-guard-indicators/1",
        "version": int(version),
        "generated": now.isoformat().replace("+00:00", "Z"),
        "source": "Amnesty Tech, Citizen Lab, Kaspersky and others, via the STIX2 files listed in mvt-project/mvt-indicators",
        "sets": sets,
        **{k: sorted(v) for k, v in total.items()},
    }
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print({k: len(v) for k, v in total.items()}, os.path.getsize(dst), "bytes")

if __name__ == "__main__":
    main(*sys.argv[1:4])
