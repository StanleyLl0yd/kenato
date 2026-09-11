import java.io.File

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

val releaseKeystorePath = providers.environmentVariable("KENATO_KEYSTORE_PATH").orNull
val releaseStorePassword = providers.environmentVariable("KENATO_KEYSTORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("KENATO_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("KENATO_KEY_PASSWORD").orNull
val m3NativeJniDir = layout.buildDirectory.dir("generated/m3JniLibs")
val m3NativeJniPath = m3NativeJniDir.get().asFile.absolutePath

val releaseSigningValues = listOf(
    releaseKeystorePath,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
)
val hasAnyReleaseSigning = releaseSigningValues.any { !it.isNullOrBlank() }
val hasReleaseSigning = releaseSigningValues.all { !it.isNullOrBlank() }

check(!hasAnyReleaseSigning || hasReleaseSigning) {
    "Release signing configuration is incomplete; set all four Kenato release-signing variables or none"
}

android {
    namespace = "com.sl.kenato"
    compileSdk = 37
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.sl.kenato"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0-dev"

        ndk {
            abiFilters += setOf("armeabi-v7a", "arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(requireNotNull(releaseKeystorePath))
                storePassword = requireNotNull(releaseStorePassword)
                keyAlias = requireNotNull(releaseKeyAlias)
                keyPassword = requireNotNull(releaseKeyPassword)
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    buildFeatures {
        compose = true
        buildConfig = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
    }

    sourceSets {
        getByName("main") {
            // The native build is an explicit CI/release prerequisite, so this is a static input.
            // Resolve the Provider before passing it to AGP's legacy source-set API: AGP 9 expects
            // a directory path here rather than a Provider or File instance.
            jniLibs.directories.add(m3NativeJniPath)
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

val verifyM3NativeLibraries = tasks.register("verifyM3NativeLibraries") {
    inputs.dir(m3NativeJniPath)

    doLast {
        val expected = setOf(
            "armeabi-v7a/libkenato_session_jni.so",
            "arm64-v8a/libkenato_session_jni.so",
            "x86_64/libkenato_session_jni.so",
        )
        val root = File(m3NativeJniPath)
        val actual = if (root.isDirectory) {
            root.walkTopDown()
                .filter { it.isFile && it.extension == "so" }
                .map { it.relativeTo(root).invariantSeparatorsPath }
                .toSet()
        } else {
            emptySet()
        }

        check(actual == expected) {
            "M3 JNI libraries are missing or unexpected. Run scripts/build_android_native.sh first. Expected=$expected actual=$actual"
        }
        expected.forEach { relative ->
            val library = root.resolve(relative)
            check(library.isFile && library.length() > 0L) {
                "M3 JNI library is missing or empty: $relative"
            }
        }
    }
}

tasks.named("preBuild").configure {
    dependsOn(verifyM3NativeLibraries)
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.zxing.core)

    debugImplementation(libs.androidx.compose.ui.tooling)
    testImplementation(libs.junit4)
}
