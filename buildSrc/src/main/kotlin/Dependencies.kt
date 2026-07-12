/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
// Project-wide dependency versions
object Versions {
    // Android
    const val compileSdk = 34
    const val minSdk = 26
    const val targetSdk = 34
    const val versionCode = 1
    const val versionName = "1.0.0"

    // Kotlin
    const val kotlin = "1.9.21"
    const val kotlinCoroutines = "1.7.3"
    const val kotlinSerialization = "1.6.2"
    const val kotlinImmutable = "0.3.6"

    // AndroidX
    const val coreKtx = "1.12.0"
    const val appcompat = "1.6.1"
    const val activity = "1.8.1"
    const val lifecycle = "2.6.2"
    const val navigation = "2.7.5"
    const val compose = "1.5.6"
    const val composeBom = "2023.10.01"
    const val room = "2.6.1"
    const val work = "2.8.1"
    const val startup = "1.1.1"
    const val dataStore = "1.0.0"
    const val security = "1.1.0-alpha06"

    // Compose Libraries
    const val accompanist = "0.32.0"
    const val composeNavigation = "2.7.5"
    const val constraintLayout = "1.0.1"

    // Dependency Injection
    const val hilt = "2.48.1"
    const val hiltAndroidX = "1.1.0"
    const val hiltNavigationCompose = "1.1.0"
    const val hiltWork = "1.1.0"

    // Network
    const val okhttp = "4.12.0"
    const val retrofit = "2.9.0"
    const val retrofitSerialization = "1.0.0"
    const val okhttpLogging = "4.12.0"

    // PDF Generation
    const val iText7 = "7.2.5"
    const val apachePdfBox = "2.0.29"

    // Bluetooth
    const val bthelper = "2.4.0"

    // Testing
    const val junit = "5.10.1"
    const val junitJupiter = "5.10.1"
    const val mockk = "1.13.8"
    const val turbine = "1.1.0"
    const val androidxTest = "1.5.2"
    const val espresso = "3.5.1"
    const val composeTesting = "1.5.4"
    const val robolectric = "4.11.1"
    const val truth = "1.1.5"
    const val androidxJunit = "1.1.5"

    // Debugging
    const val timber = "5.0.1"
    const val leakCanary = "2.12"

    // Shizuku (root-free ADB access)
    const val shizuku = "13.1.5"

    // Protobuf
    const val protobuf = "3.25.1"
    const val protobufKotlinLite = "3.25.1"
}

object Dependencies {
    // AndroidX Core
    val coreKtx = "androidx.core:core-ktx:${Versions.coreKtx}"
    val appcompat = "androidx.appcompat:appcompat:${Versions.appcompat}"
    val activity = "androidx.activity:activity-compose:${Versions.activity}"

    // Lifecycle
    val lifecycleRuntime = "androidx.lifecycle:lifecycle-runtime-ktx:${Versions.lifecycle}"
    val lifecycleViewModel = "androidx.lifecycle:lifecycle-viewmodel-ktx:${Versions.lifecycle}"
    val lifecycleLiveData = "androidx.lifecycle:lifecycle-livedata-ktx:${Versions.lifecycle}"
    val lifecycleCompose = "androidx.lifecycle:lifecycle-runtime-compose:${Versions.lifecycle}"

    // Navigation
    val navigationCompose = "androidx.navigation:navigation-compose:${Versions.navigation}"

    // Compose
    val composeBom = "androidx.compose:compose-bom:${Versions.composeBom}"
    val composeUi = "androidx.compose.ui:ui"
    val composeUiTooling = "androidx.compose.ui:ui-tooling"
    val composeUiToolingPreview = "androidx.compose.ui:ui-tooling-preview"
    val composeMaterial3 = "androidx.compose.material3:material3"
    val composeMaterialIcons = "androidx.compose.material:material-icons-extended"

    // Hilt
    val hiltAndroid = "com.google.dagger:hilt-android:${Versions.hilt}"
    val hiltCompiler = "com.google.dagger:hilt-compiler:${Versions.hilt}"
    val hiltNavigationCompose = "androidx.hilt:hilt-navigation-compose:${Versions.hiltNavigationCompose}"
    val hiltWork = "androidx.hilt:hilt-work:${Versions.hiltWork}"

    // Room
    val roomRuntime = "androidx.room:room-runtime:${Versions.room}"
    val roomKtx = "androidx.room:room-ktx:${Versions.room}"
    val roomCompiler = "androidx.room:room-compiler:${Versions.room}"

    // Coroutines
    val coroutinesCore = "org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.kotlinCoroutines}"
    val coroutinesAndroid = "org.jetbrains.kotlinx:kotlinx-coroutines-android:${Versions.kotlinCoroutines}"

    // Serialization
    val kotlinSerialization = "org.jetbrains.kotlinx:kotlinx-serialization-json:${Versions.kotlinSerialization}"

    // Testing
    val junit = "org.junit.jupiter:junit-jupiter:${Versions.junit}"
    val mockk = "io.mockk:mockk:${Versions.mockk}"
    val turbine = "app.cash.turbine:turbine:${Versions.turbine}"
}
