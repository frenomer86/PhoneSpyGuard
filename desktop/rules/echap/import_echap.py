#!/usr/bin/env python3
"""Rebuild the `indicators.stalkerware` block of desktop-bundle.json from the
Echap stalkerware indicators (https://github.com/AssoEchap/stalkerware-indicators,
CC BY 4.0).

    python3 -I import_echap.py <echap-dir> <desktop-bundle.json>

<echap-dir> holds Echap's ioc.yaml and samples.csv. Only the stalkerware
block is replaced; rules and the other indicator lists are left as they are.
Re-sign the bundle afterwards (psg-sign sign-once, then psg-sign log).

What is taken, per family: server domains and addresses (c2), the websites
that sell it, and the SHA-256 of every known installer sample. Server
addresses on shared CDN ranges are dropped, since thousands of unrelated
sites answer from them.
"""
import csv
import ipaddress
import json
import re
import sys

import yaml

# Cloudflare's published ranges (https://www.cloudflare.com/ips/).
SHARED_RANGES = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)]

HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def hosts(values, family, what, dropped):
    out = set()
    for v in values or []:
        v = str(v).strip().lower().rstrip(".")
        if HOST.match(v):
            out.add(v)
        else:
            dropped.append(f"{family}: {what} {v!r} is not a host name")
    return sorted(out)


def addresses(values, family, dropped):
    out = set()
    for v in values or []:
        try:
            ip = ipaddress.ip_address(str(v).strip())
        except ValueError:
            dropped.append(f"{family}: address {v!r} is not an IP address")
            continue
        if any(ip in n for n in SHARED_RANGES):
            dropped.append(f"{family}: address {ip} is on a shared CDN range")
            continue
        out.add(str(ip))
    return sorted(out, key=lambda a: ipaddress.ip_address(a).packed)


def main(echap_dir, bundle_path):
    with open(f"{echap_dir}/ioc.yaml", encoding="utf-8") as f:
        families = yaml.safe_load(f)
    alias = {}
    for fam in families:
        for n in [fam["name"], *(fam.get("names") or [])]:
            alias[str(n).lower()] = fam["name"]

    samples = {}
    dropped = []
    with open(f"{echap_dir}/samples.csv", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            h = row["SHA256"].strip().lower()
            owner = alias.get(row["App"].strip().lower())
            if not owner:
                dropped.append(f"sample {h}: unknown app {row['App']!r}")
            elif not SHA256.match(h):
                dropped.append(f"sample for {owner}: {h!r} is not a SHA-256")
            else:
                samples.setdefault(owner, set()).add(h)

    out, ids = [], set()
    for fam in sorted(families, key=lambda f: f["name"].lower()):
        name = fam["name"]
        fid = "SW-" + re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-")
        if fid in ids:
            sys.exit(f"duplicate indicator id {fid}")
        ids.add(fid)
        c2 = fam.get("c2") or {}
        entry = {
            "id": fid,
            "name": name,
            "domains": hosts(c2.get("domains"), name, "server", dropped),
            "ips": addresses(c2.get("ips"), name, dropped),
            "websites": hosts(fam.get("websites"), name, "website", dropped),
            "sha256": sorted(samples.get(name, ())),
        }
        if any(entry[k] for k in ("domains", "ips", "websites", "sha256")):
            out.append(entry)

    with open(bundle_path, encoding="utf-8") as f:
        bundle = json.load(f)
    bundle["indicators"]["stalkerware"] = out
    with open(bundle_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)
        f.write("\n")

    count = lambda k: sum(len(e[k]) for e in out)
    print(f"{len(out)} families: {count('domains')} server domains, {count('ips')} addresses, "
          f"{count('websites')} websites, {count('sha256')} installer hashes")
    for d in dropped:
        print("dropped:", d)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
