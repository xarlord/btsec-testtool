/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool

import android.Manifest
import android.os.Build
import androidx.test.rule.GrantPermissionRule
import org.junit.rules.TestRule

/**
 * Grants the Bluetooth runtime permission required by the Android version under test.
 *
 * Android 12+ uses the Nearby Devices permissions; Android 11 and below require
 * location permission for Bluetooth discovery. Granting a permission unavailable on
 * the current API level makes [GrantPermissionRule] fail before a test begins.
 */
fun bluetoothRuntimePermissionRule(): TestRule =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        GrantPermissionRule.grant(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
        )
    } else {
        GrantPermissionRule.grant(Manifest.permission.ACCESS_FINE_LOCATION)
    }
