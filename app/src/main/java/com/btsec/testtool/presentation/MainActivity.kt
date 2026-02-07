/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.core.content.ContextCompat
import com.btsec.testtool.presentation.navigation.BTSecNavGraph
import com.btsec.testtool.presentation.theme.BTSecTheme
import dagger.hilt.android.AndroidEntryPoint
import timber.log.Timber

/**
 * Main (and only) Activity for BTSec Test Tool.
 *
 * This activity hosts all Compose UI screens and manages the single-activity navigation.
 * All screens are implemented as Composable functions.
 */
@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    // ViewModels
    private val viewModel: MainViewModel by viewModels()

    // Permission request launcher
    private val bluetoothPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        viewModel.onPermissionResult(allGranted)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Check and request permissions
        checkAndRequestPermissions()

        setContent {
            BTSecTheme {
                Surface {
                    BTSecNavGraph()
                }
            }
        }

        Timber.d("MainActivity created")
    }

    /**
     * Check if all required permissions are granted.
     */
    private fun checkAndRequestPermissions() {
        val permissions = mutableListOf<String>()

        // Bluetooth permissions based on Android version
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // Android 12+ (API 31+)
            permissions.add(Manifest.permission.BLUETOOTH_SCAN)
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            // Pre-Android 12
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }

        // Location permission (required for scanning)
        permissions.add(Manifest.permission.ACCESS_FINE_LOCATION)
        permissions.add(Manifest.permission.ACCESS_COARSE_LOCATION)

        // Android 13+ notification permission
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        // Check which permissions are not granted
        val notGranted = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (notGranted.isNotEmpty()) {
            bluetoothPermissionLauncher.launch(notGranted.toTypedArray())
        } else {
            viewModel.onPermissionResult(true)
        }
    }

    override fun onResume() {
        super.onResume()
        Timber.d("MainActivity resumed")
    }

    override fun onPause() {
        super.onPause()
        Timber.d("MainActivity paused")
    }

    override fun onDestroy() {
        super.onDestroy()
        Timber.d("MainActivity destroyed")
    }
}
