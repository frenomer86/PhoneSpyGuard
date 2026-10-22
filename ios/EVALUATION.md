# Measured results (review finding M6)

What has been measured for the iPhone device check, and what has not.

## Measured

- **Archive reader speed:** a 206 MB sysdiagnose `.tar.gz` is read in one
  streaming pass in 2.6 s on one laptop core (plain-Swift gzip and tar
  reader, no temporary files).
- **Indicator coverage:** 83 process names, 49 paths, 15 file names and
  4,980 domains from the 18 STIX2 sets MVT lists (Pegasus, Predator,
  KingSpawn, Operation Triangulation and others), shipped as a signed file.
- **Rule behaviour:** 52 automated tests, including the shared conformance
  fixtures used by the Android and desktop engines, and synthetic infected
  and clean sysdiagnose archives (shutdown log, running processes and crash
  reports).

## Not measured yet

- Diagnostic archives from real infected iPhones. The analyser is tested on
  synthetic archives built from published indicators only. MVT's public test
  material is iTunes backups, which this check does not read.
- False alarms on a large set of real, clean sysdiagnose archives.
- Real devices: the app has not run on an iPhone yet.
