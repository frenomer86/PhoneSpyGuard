/// Compile-time choices for this build.
enum BuildFlags {
    /// Accept rules signed with the development keys in `trusted-keys.json`
    /// (review finding H6). Only Debug builds and lab builds made with the
    /// `PSG_ALLOW_DEV_KEYS` Swift flag do; a release build refuses them, so a
    /// build handed to real users needs real, offline-held release keys.
    static var allowDevelopmentKeys: Bool {
        #if DEBUG || PSG_ALLOW_DEV_KEYS
        return true
        #else
        return false
        #endif
    }
}
