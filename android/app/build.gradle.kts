plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.phishguard.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.phishguard.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 2
        versionName = "1.1"

        // Override for local development: ./gradlew installDebug -Pphishguard.serverUrl=http://10.0.2.2:3000
        val serverUrl = project.findProperty("phishguard.serverUrl") ?: "https://phishguard.sonu-kumar.in"
        buildConfigField("String", "SERVER_URL", "\"$serverUrl\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.4")

    testImplementation("junit:junit:4.13.2")
    // The real org.json, so JSON code can be unit-tested on the JVM (android.jar only has stubs).
    testImplementation("org.json:json:20240303")
}
