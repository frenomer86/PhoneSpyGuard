plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.phonespyguard.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.phonespyguard.app"
        minSdk = 28 // Android 9 (NFR-CMP-01)
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            // R8 shrink/obfuscate + Play code transparency are configured for
            // release per NFR-SEC-04; signing config is supplied by CI.
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // The app is focused on one job — checking this device for spyware and
    // keeping a tamper-evident record — so it depends only on the modules that
    // serve it. The scam checker, account audit and phone-number guard
    // (core:scam / core:accounts / core:phone) stay in the repo and keep their
    // tests, but are no longer part of the shipped app; the market-research
    // thread decides what to bring back and strengthen next.
    implementation(project(":core:detection"))
    implementation(project(":core:evidence"))
    implementation(project(":core:watch"))
    implementation(project(":core:safety"))

    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.work:work-runtime-ktx:2.9.1")

    // Encrypted evidence store and baseline (NFR-SEC-12, security review C3).
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // App lock via biometric / device credential (NFR-SEC-06, security review C4).
    implementation("androidx.biometric:biometric:1.1.0")
    // biometric pulls in fragment 1.2.5, whose FragmentActivity rejects the
    // request codes activity 1.9 issues and crashes the permission prompt.
    implementation("androidx.fragment:fragment-ktx:1.8.5")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
