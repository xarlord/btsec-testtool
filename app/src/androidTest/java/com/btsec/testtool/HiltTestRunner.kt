/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool

import android.app.Application
import android.content.Context
import androidx.test.runner.AndroidJUnitRunner
import dagger.hilt.android.testing.HiltTestApplication

/**
 * Custom instrumentation runner for instrumented (E2E) tests.
 *
 * Loads [HiltTestApplication] as the test Application via [newApplication],
 * which resolves it through the *test* classloader. This is the approach
 * recommended by both Hilt and AndroidX for running `@HiltAndroidTest`
 * classes.
 *
 * Setting `android:name` to `HiltTestApplication` in the androidTest
 * manifest does NOT work reliably because the Android framework then tries
 * to instantiate the class from the base application classloader, where the
 * `hilt-android-testing` runtime classes are not dexed — resulting in:
 *
 *   ClassNotFoundException: dagger.hilt.android.testing.HiltTestApplication
 *
 * Overriding newApplication() forces the class to be loaded from the test
 * APK's classloader, where `androidTestImplementation("...hilt-android-testing")`
 * places it. See issue #368.
 *
 * Configured in build.gradle.kts via:
 *   testInstrumentationRunner = "com.btsec.testtool.HiltTestRunner"
 */
class HiltTestRunner : AndroidJUnitRunner() {

    override fun newApplication(
        cl: ClassLoader?,
        className: String?,
        context: Context?
    ): Application {
        // Always use HiltTestApplication regardless of the className the
        // framework requests, so the production BtSecTestToolApplication is
        // never instantiated during tests.
        return super.newApplication(cl, HiltTestApplication::class.java.name, context)
    }
}
