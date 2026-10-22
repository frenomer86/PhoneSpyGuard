plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
}

dependencies {
    implementation(project(":core:detection"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    jvmToolchain(21)
    explicitApi()
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "skipped", "failed") }
    // Show the evaluation report the harness prints.
    testLogging { showStandardStreams = true }
}
