package com.btsec.testtool.presentation

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import com.btsec.testtool.presentation.navigation.BTSecNavGraph
import com.btsec.testtool.presentation.theme.BTSecTheme
import dagger.hilt.android.AndroidEntryPoint
import timber.log.Timber

/**
 * Main (and only) Activity for BTSec Test Tool.
 *
 * Aggressively requests all Bluetooth permissions on launch AND resume.
 */
@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val bluetoothPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        val denied = permissions.filterValues { !it }.keys
        Timber.i("Permission result: allGranted=$allGranted, denied=$denied")
        viewModel.onPermissionResult(allGranted)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request permissions IMMEDIATELY before setting content
        requestBluetoothPermissions()

        setContent {
            BTSecTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    BTSecNavGraph()
                }
            }
        }

        Timber.d("MainActivity created")
    }

    override fun onResume() {
        super.onResume()
        // Re-check permissions on resume — if user navigated back from Settings
        // and still hasn't granted, re-request
        val missing = getMissingPermissions()
        if (missing.isNotEmpty()) {
            Timber.i("onResume: requesting missing permissions: $missing")
            bluetoothPermissionLauncher.launch(missing.toTypedArray())
        }
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

    /**
     * Get list of required Bluetooth permissions for current Android version.
     */
    private fun getRequiredPermissions(): List<String> {
        val perms = mutableListOf<String>()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // Android 12+ (API 31+)
            perms.add(Manifest.permission.BLUETOOTH_SCAN)
            perms.add(Manifest.permission.BLUETOOTH_CONNECT)
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            // Pre-Android 12 needs location for BT scanning
            perms.add(Manifest.permission.ACCESS_FINE_LOCATION)
            perms.add(Manifest.permission.ACCESS_COARSE_LOCATION)
        }

        // Always request location — some OEMs need it even on Android 12+
        perms.add(Manifest.permission.ACCESS_FINE_LOCATION)
        perms.add(Manifest.permission.ACCESS_COARSE_LOCATION)

        // Android 13+ notification permission
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            perms.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        return perms.distinct()
    }

    /**
     * Get permissions that are NOT yet granted.
     */
    private fun getMissingPermissions(): List<String> {
        return getRequiredPermissions().filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
    }

    /**
     * Force request Bluetooth permissions.
     */
    private fun requestBluetoothPermissions() {
        val missing = getMissingPermissions()
        if (missing.isNotEmpty()) {
            Timber.i("Requesting permissions: $missing")
            bluetoothPermissionLauncher.launch(missing.toTypedArray())
        } else {
            Timber.i("All permissions already granted")
            viewModel.onPermissionResult(true)
        }
    }
}
