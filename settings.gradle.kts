pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
    // Plugin versions are pinned centrally here, not in the root build script,
    // so a plugin is resolved only when a module actually applies it. The
    // Android/Compose plugins are therefore fetched only when the SDK-gated
    // :app module is in the build; the pure-JVM core still builds with just a
    // JDK (NFR-MNT-01), with no attempt to resolve the Android Gradle Plugin.
    plugins {
        id("org.jetbrains.kotlin.jvm") version "2.0.21"
        id("org.jetbrains.kotlin.plugin.serialization") version "2.0.21"
        id("org.jetbrains.kotlin.android") version "2.0.21"
        id("org.jetbrains.kotlin.plugin.compose") version "2.0.21"
        id("com.android.application") version "8.7.2"
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "phone-spy-guard"

// Pure-JVM core: the detection engine, the evidence timeline, the change
// watcher and the phone-number guard. No Android dependencies (NFR-MNT-01), so
// they build and test with only a JDK.
include(":core:detection")
include(":core:evidence")
include(":core:watch")
include(":core:phone")
include(":core:scam")
include(":core:accounts")
include(":core:safety")
include(":core:eval")

// Cross-engine conformance: runs the shared fixtures in desktop/conformance so
// the Kotlin core and the Rust desktop core are proven to score and log
// identically. Included only when the desktop/ tree is present.
if (rootDir.resolve("desktop/conformance").exists()) {
    include(":core:conformance")
}

// The Android app module needs the Android SDK and the Android Gradle Plugin.
// It is included only when an SDK is configured, so the core still builds with
// just a JDK (e.g. in CI or this environment). Android Studio writes
// local.properties on first open, which flips this on automatically.
val androidSdkAvailable = System.getenv("ANDROID_HOME") != null ||
    System.getenv("ANDROID_SDK_ROOT") != null ||
    rootDir.resolve("local.properties").exists()

if (androidSdkAvailable) {
    include(":app")
} else {
    gradle.rootProject {
        logger.lifecycle(
            "[phone-spy-guard] Android SDK not found — the :app module is skipped. " +
                "Open the project in Android Studio (or set ANDROID_HOME) to build the app.",
        )
    }
}
