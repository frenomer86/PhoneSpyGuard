// Plugin versions are pinned centrally in settings.gradle.kts (pluginManagement),
// not here, so the Android/Compose plugins are resolved only when the SDK-gated
// :app module actually applies them. The pure-JVM core modules apply
// kotlin("jvm")/serialization (version-less) and build with just a JDK
// (NFR-MNT-01); :app applies the Android/Compose plugins (version-less). Both
// get one shared plugin classloader because every version is pinned in one place.

// Repositories are declared centrally in settings.gradle.kts
// (dependencyResolutionManagement), so modules do not declare their own.

allprojects {
    group = "com.phonespyguard"
    version = "0.1.0"
}
