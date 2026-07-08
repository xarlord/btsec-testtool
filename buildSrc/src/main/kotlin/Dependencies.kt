/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */

// Project-wide dependency versions (updated 2026-06-21 for Gradle 8.11.1 / Kotlin 2.1.0)
object Versions {
    // Android
    const val compileSdk = 35
    const val minSdk = 24
    const val targetSdk = 35
    const val versionCode = 1
    const val versionName = "1.0.0"

    // Kotlin
    const val kotlin = "2.1.0"
    const val kotlinCoroutines = "1.9.0"
    const val kotlinSerialization = "1.7.3"
    const val kotlinImmutable = "0.3.8"

    // AndroidX
    const val coreKtx = "1.15.0"
    const val appcompat = "1.7.0"
    const val activity = "1.9.3"
    const val lifecycle = "2.8.7"
    const val navigation = "2.8.5"
    const val compose = "2.1.0" // matches Kotlin 2.1.0 (managed by kotlin.plugin.compose)
    const val composeBom = "2024.12.01"
    const val room = "2.6.1"
    const val work = "2.10.0"
    const val startup = "1.1.1"
    const val dataStore = "1.1.1"
    const val security = "1.1.0-alpha06"

    // Compose Libraries
    const val accompanist = "0.36.0"
    const val composeNavigation = "2.8.5"
    const val constraintLayout = "1.1.0"

    // Dependency Injection
    const val hilt = "2.53.1"
    const val hiltAndroidX = "1.2.0"
    const val hiltNavigationCompose = "1.2.0"
    const val hiltWork = "1.2.0"

    // Network
    const val okhttp = "4.12.0"
    const val retrofit = "2.11.0"
    const val retrofitSerialization = "1.0.0"
    const val okhttpLogging = "4.12.0"

    // PDF Generation
    const val iText7 = "7.2.5"
    const val apachePdfBox = "2.0.32"

    // Bluetooth
    const val bthelper = "2.4.0"

    // Testing
    const val junit = "5.11.4"
    const val junitJupiter = "5.11.4"
    const val mockk = "1.13.13"
    const val turbine = "1.2.0"
    const val androidxTest = "1.6.1"
    const val espresso = "3.6.1"
    const val composeTesting = "1.7.6"
    const val robolectric = "4.14.1"
    const val truth = "1.4.4"
    const val androidxJunit = "1.2.1"

    // Debugging
    const val timber = "5.0.1"
    const val leakCanary = "2.14"

    // Protobuf
    const val protobuf = "3.25.5"
    const val protobufKotlinLite = "3.25.5"
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
