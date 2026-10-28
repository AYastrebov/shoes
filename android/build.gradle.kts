plugins {
    alias(libs.plugins.android.library)
    // kotlin-android removed: AGP 9.0 has built-in Kotlin support
}

android {
    namespace = "com.shoesproxy"
    compileSdk = 35

    defaultConfig {
        minSdk = 21
        consumerProguardFiles("consumer-rules.pro")
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

    // The JNI libraries cargo-ndk writes to src/main/jniLibs are picked up
    // from there by default; naming the directory again through srcDirs is
    // deprecated in AGP 9.4.
}
