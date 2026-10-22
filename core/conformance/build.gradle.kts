plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
}

// The shared conformance fixtures and the Kotlin side of the test live in the
// desktop tree (written by the desktop build). This module pulls them into the
// Kotlin core build so `./gradlew test` proves both engines agree.
val conformanceDir = rootProject.projectDir.resolve("desktop/conformance")

dependencies {
    testImplementation(project(":core:detection"))
    testImplementation(project(":core:evidence"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    jvmToolchain(21)
}

sourceSets {
    test {
        val kotlinDir = conformanceDir.resolve("kotlin")
        if (kotlinDir.exists()) kotlin.srcDir(kotlinDir)
    }
}

tasks.test {
    useJUnitPlatform()
    // The test reads its fixtures from this directory.
    environment("PSG_CONFORMANCE_DIR", conformanceDir.absolutePath)
    onlyIf { conformanceDir.exists() }
    testLogging { events("passed", "skipped", "failed") }
}
