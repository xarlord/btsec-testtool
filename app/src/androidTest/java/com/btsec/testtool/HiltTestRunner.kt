/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool

import android.app.Application
import android.content.Context
import androidx.test.runner.AndroidJUnitRunner
import dagger.hilt.android.testing.HiltTestRunner

/**
 * Custom test runner that uses Hilt for dependency injection in instrumented tests.
 *
 * Required for @HiltAndroidTest to work properly.
 * This replaces the default AndroidJUnitRunner so that Hilt can inject
 * test dependencies and replace production modules with test modules.
 */
class HiltTestRunner : HiltTestRunner() {
    override fun newApplication(
        cl: ClassLoader?,
        className: String?,
        context: Context?
    ): Application {
        return super.newApplication(cl, HiltTestApplication::class.java.name, context)
    }
}
