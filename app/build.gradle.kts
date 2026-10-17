import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

val appVersionName = providers.gradleProperty("mihomo.versionName").getOrElse("0.1.0")
// CI passes the GitHub run number (BUILD_NUMBER); local builds are build 1.
val buildNumber = (System.getenv("BUILD_NUMBER") ?: "1").toIntOrNull() ?: 1

// Release signing: CI generates a throw-away keystore per run and exports these variables
// (never committed; a fixed keystore goes into GitHub Secrets only after the user agrees).
// Without them the release build falls back to the debug key so local builds still assemble.
val ciKeystore = System.getenv("MIHOMO_KEYSTORE")
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "io.github.astemo6.mihomo"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.astemo6.mihomo"
        minSdk = 26
        targetSdk = 35
        versionCode = buildNumber
        versionName = appVersionName
        vectorDrawables { useSupportLibrary = true }
    }

    signingConfigs {
        create("release") {
            when {
                ciKeystore != null -> {
                    storeFile = file(ciKeystore)
                    storePassword = System.getenv("MIHOMO_KEYSTORE_PASSWORD")
                    keyAlias = System.getenv("MIHOMO_KEY_ALIAS") ?: "mihomo"
                    keyPassword = System.getenv("MIHOMO_KEY_PASSWORD") ?: System.getenv("MIHOMO_KEYSTORE_PASSWORD")
                }
                keystoreProps.getProperty("storeFile") != null -> {
                    storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                    storePassword = keystoreProps.getProperty("storePassword")
                    keyAlias = keystoreProps.getProperty("keyAlias")
                    keyPassword = keystoreProps.getProperty("keyPassword")
                }
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            val release = signingConfigs.getByName("release")
            signingConfig = if (release.storeFile != null) release else signingConfigs.getByName("debug")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    // Two APKs per release: universal (arm64-v8a + x86_64 from the AAR) and arm64-v8a only.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a")
            isUniversalApk = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    androidResources {
        // zh-Hans is the default (values/), plus zh-Hant and English.
        @Suppress("UnstableApiUsage")
        generateLocaleConfig = true
    }
    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/*.kotlin_module")
        jniLibs.useLegacyPackaging = false
    }
    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
}

dependencies {
    // gomobile bind output of core/ (Java package `libmihomo`), built by CI into app/libs (not committed).
    implementation(files("libs/libmihomo.aar"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    implementation(libs.okhttp)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    debugImplementation(libs.compose.ui.tooling)
}
