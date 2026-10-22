# Phone Spy Guard release rules.
# R8 shrinking/obfuscation is on for release (NFR-SEC-04). The core modules are
# plain Kotlin/JVM and need no special keep rules; add rules here only as the
# app grows (e.g. for any reflection-based serialization).
