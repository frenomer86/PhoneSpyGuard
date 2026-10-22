# Builds the PSGCompanion test fixtures: small synthetic sysdiagnose archives,
# a STIX2 indicator file, and gzip streams that exercise every DEFLATE block type.
import gzip, hashlib, io, json, os, random, sys, tarfile, time, zlib

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
random.seed(42)
root = "sysdiagnose_2026.10.20_09-14-03+0100_iPhone-OS_iPhone_22H31"
logdir = root + "/system_logs.logarchive/Extra"

def shutdown_log(blocks):
    lines = []
    for t, procs in blocks:
        lines.append("After 2.01s, these clients are still here:")
        for pid, path in procs:
            lines.append(f"\t\tremaining client pid: {pid} ({path})")
        lines.append(f"SIGTERM: [{t}] (MAKESHUTDOWNLOG)")
    return "\n".join(lines) + "\n"

system = [(101, "/System/Library/PrivateFrameworks/MediaRemote.framework/Support/mediaremoted"),
          (230, "/usr/libexec/backboardd"),
          (512, "/private/var/containers/Bundle/Application/1A2B3C4D-0000-1111-2222-333344445555/Signal.app/Signal")]
infected = system + [(777, "/private/var/db/com.apple.xpc.roleaccountd.staging/bh"),
                     (778, "/private/var/tmp/netwatchd"),
                     (779, "/private/var/mobile/Library/Caches/com.example.helper/helper")]

running_system = ["/usr/libexec/backboardd", "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
                  "/private/var/containers/Bundle/Application/9F8E7D6C-0000-1111-2222-333344445555/My Notes.app/My Notes -launchedBy springboard"]

def add(tar, name, data, mtime=1760951643):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mtime = mtime
    tar.addfile(ti, io.BytesIO(data))

def ps_txt(paths):
    # The layout of `ps` in a real sysdiagnose: fixed columns, COMMAND last.
    head = "USER               UID PRSNA   PID  PPID        F  %CPU %MEM PRI NI      VSZ    RSS WCHAN    TT  STAT STARTED      TIME COMMAND\n"
    rows = [f"root                 0     -     1     0     4004   0.0  0.1  37  0 408226256   9424 -        ??  Ss    9:14AM   0:31.20 /sbin/launchd\n"]
    for i, p in enumerate(paths):
        rows.append(f"mobile             501     -  {300 + i:4d}     1     4004   0.0  0.2  31  0 408512048  12016 -        ??  Ss    9:14AM   0:01.02 {p}\n")
    rows.append("root                 0     -     0     0        0   0.3  2.1   0  0        0      0 -        ??  Rs    9:13AM  12:01.11 kernel_task\n")
    # Many repeats so the archive is the size a real one compresses to.
    return (head + "".join(rows) * 300).encode()

def archive(path, log, extra, fmt, running):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tar:
        d = tarfile.TarInfo(root); d.type = tarfile.DIRTYPE; tar.addfile(d)
        # Incompressible and compressible filler so the gzip stream has stored,
        # fixed and dynamic blocks, like a real sysdiagnose.
        add(tar, root + "/logs/random.bin", random.randbytes(300_000))
        add(tar, root + "/ps.txt", ps_txt(running))
        add(tar, logdir + "/shutdown.log", log.encode())
        for name, data in extra:
            add(tar, root + "/" + name, data)
    with open(path, "wb") as f:
        f.write(gzip.compress(buf.getvalue(), 6, mtime=0))

archive(f"{out}/sysdiagnose-infected.tar.gz",
        shutdown_log([(1760900000, infected), (1760950000, infected[:4]), (1760951000, system)]),
        [("crashes_and_spins/msgacntd-2026-10-19-221530.ips", b'{"procName":"msgacntd"}'),
         ("crashes_and_spins/MobileSafari-2026-10-19-101010.ips", b'{}')],
        tarfile.GNU_FORMAT,
        running_system + ["/private/var/db/com.apple.xpc.roleaccountd.staging/bh", "/private/var/db/.ckmd/ckmd"])
archive(f"{out}/sysdiagnose-clean.tar.gz",
        shutdown_log([(1760900000, system), (1760950000, system[:2])]),
        [("crashes_and_spins/MobileSafari-2026-10-19-101010.ips", b'{}')],
        tarfile.PAX_FORMAT,
        running_system)

with open(f"{out}/shutdown.log", "w") as f:
    f.write(shutdown_log([(1760900000, infected)]))

stix = {"type": "bundle", "id": "bundle--test", "objects": [
    {"type": "malware", "id": "malware--1", "name": "TestSpy", "is_family": True},
    {"type": "indicator", "id": "indicator--1", "pattern_type": "stix", "pattern": "[process:name='helper']"},
    {"type": "indicator", "id": "indicator--2", "pattern_type": "stix", "pattern": "[domain-name:value='evil-cdn.example']"},
    {"type": "indicator", "id": "indicator--3", "pattern_type": "stix", "pattern": "[url:value='https://track.badlink.example/x?y=1']"},
    {"type": "indicator", "id": "indicator--4", "pattern_type": "stix", "pattern": "[file:name='payload.dylib' OR process:name='it\\'sd']"}]}
with open(f"{out}/test-indicators.stix2", "w") as f:
    json.dump(stix, f, indent=1)

# DEFLATE coverage: stored (level 0), fixed Huffman, dynamic, plus a long
# run that needs maximum-distance and maximum-length matches.
text = (" ".join(random.choice(["shutdown", "pid", "remaining", "client", "launchd", "the", "a"]) for _ in range(60_000))).encode()
data = text + random.randbytes(70_000) + b"z" * 100_000 + text[:40_000]
cases = {}
for name, level, strategy in [("stored", 0, zlib.Z_DEFAULT_STRATEGY), ("fixed", 6, zlib.Z_FIXED),
                              ("dynamic", 9, zlib.Z_DEFAULT_STRATEGY), ("fast", 1, zlib.Z_DEFAULT_STRATEGY)]:
    c = zlib.compressobj(level, zlib.DEFLATED, 31, 9, strategy)
    gz = c.compress(data) + c.flush()
    with open(f"{out}/deflate-{name}.gz", "wb") as f:
        f.write(gz)
# Two gzip members back to back, as `cat a.gz b.gz` makes.
with open(f"{out}/deflate-multimember.gz", "wb") as f:
    f.write(gzip.compress(data[:5000], mtime=0) + gzip.compress(data[5000:9000], mtime=0))
with open(f"{out}/deflate-expected.json", "w") as f:
    json.dump({"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
               "multimemberSha256": hashlib.sha256(data[:9000]).hexdigest()}, f)
print("fixtures written")
