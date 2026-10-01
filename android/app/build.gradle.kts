plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.google.services)
}

repositories {
    google()
    mavenCentral()
}

android {
    namespace = "com.offlinewallet"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.offlinewallet"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.recyclerview)
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)
    implementation(libs.retrofit)
    implementation(libs.retrofit.gson)
    implementation(libs.retrofit.scalars)
    implementation(libs.androidx.security.crypto)
    implementation(libs.google.material)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.dynamicanimation)
    implementation(libs.androidx.cardview)
    implementation(libs.androidx.compose.material.icons)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.bouncycastle.bcprov)
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.analytics)
    implementation(libs.firebase.firestore)
    implementation(libs.firebase.auth)
    implementation(libs.firebase.messaging)
    implementation(libs.firebase.storage)
    implementation(libs.firebase.ui.firestore)
    implementation(libs.kotlinx.coroutines.play.services)
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    implementation("com.google.android.gms:play-services-base:18.5.0")
    implementation("com.google.android.gms:play-services-tasks:18.2.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.swiperefreshlayout)
    implementation(libs.jackson.cbor)
    implementation(libs.jackson.kotlin)
    implementation(libs.sqlcipher)
    implementation(libs.play.integrity)
    implementation(libs.bouncycastle.bcpkix)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}