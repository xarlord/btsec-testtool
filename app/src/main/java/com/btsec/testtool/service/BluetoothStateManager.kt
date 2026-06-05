/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.service

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.callbackFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Bluetooth adapter state: ON, OFF, TURNING_ON, TURNING_OFF, or UNAVAILABLE.
 */
enum class BluetoothState {
    ON, OFF, TURNING_ON, TURNING_OFF, UNAVAILABLE
}

/**
 * Monitors Bluetooth adapter state changes.
 */
@Singleton
class BluetoothStateManager @Inject constructor(
    @ApplicationContext private val context: Context
 ) {

    private val _bluetoothState = MutableStateFlow(BluetoothState.UNAVAILABLE)
    val bluetoothState: Flow<BluetoothState> = _bluetoothState.asStateFlow()

    private val _permissionsGranted = MutableStateFlow(false)
    val permissionsGranted: Flow<Boolean> = _permissionsGranted.asStateFlow()

    private val _hasLocationPermission = MutableStateFlow(false)
    val hasLocationPermission: Flow<Boolean> = _hasLocationPermission.asStateFlow()

    private var receiver: BroadcastReceiver? = null

    /**
    * Required Bluetooth permissions based on Android version.
    */
    val requiredPermissions: List<String>
       get() = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
           listOf(
               Manifest.permission.BLUETOOTH_SCAN,
               Manifest.permission.BLUETOOTH_CONNECT,
               Manifest.permission.BLUETOOTH_ADVERTISE,
               Manifest.permission.ACCESS_FINE_LOCATION
           )
       } else {
           listOf(
               Manifest.permission.BLUETOOTH,
               Manifest.permission.BLUETOOTH_ADMIN,
               Manifest.permission.ACCESS_FINE_LOCATION
           )
       }

    /**
    * Start monitoring Bluetooth adapter state.
    * Call this in Application.onCreate() or Activity.onStart().
    */
    fun startMonitoring() {
       updateInitialState()
       registerReceiver()
    }

    /**
    * Stop monitoring. Call in Activity.onStop() or Application.onTerminate().
    */
    fun stopMonitoring() {
       receiver?.let { context.unregisterReceiver(it) }
       receiver = null
    }

    /**
    * Check if Bluetooth is currently enabled.
    */
    fun isBluetoothEnabled(): Boolean {
       val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
       return manager?.adapter?.isEnabled == true
    }

    /**
    * Get the Bluetooth adapter, or null if unavailable.
    */
    fun getAdapter(): BluetoothAdapter? {
       val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
       return manager?.adapter
    }

    /**
    * Check all required BT permissions.
    */
    fun checkPermissions(): Boolean {
       val granted = requiredPermissions.all { perm ->
           ContextCompat.checkSelfPermission(context, perm) == PackageManager.PERMISSION_GRANTED
       }
       _permissionsGranted.value = granted
       _hasLocationPermission.value = ContextCompat.checkSelfPermission(
           context, Manifest.permission.ACCESS_FINE_LOCATION
       ) == PackageManager.PERMISSION_GRANTED
       return granted
    }

    /**
    * Observe Bluetooth state as a Flow (for Compose collectAsState).
    */
    fun observeBluetoothState(): Flow<BluetoothState> = callbackFlow {
       updateInitialState()

       val receiver = object : BroadcastReceiver() {
           override fun onReceive(ctx: Context, intent: Intent) {
               when (intent.action) {
                   BluetoothAdapter.ACTION_STATE_CHANGED -> {
                       val state = intent.getIntExtra(
                           BluetoothAdapter.EXTRA_STATE,
                           BluetoothAdapter.ERROR
                       )
                       val btState = when (state) {
                           BluetoothAdapter.STATE_ON -> BluetoothState.ON
                           BluetoothAdapter.STATE_OFF -> BluetoothState.OFF
                           BluetoothAdapter.STATE_TURNING_ON -> BluetoothState.TURNING_ON
                           BluetoothAdapter.STATE_TURNING_OFF -> BluetoothState.TURNING_OFF
                           else -> BluetoothState.UNAVAILABLE
                       }
                       _bluetoothState.value = btState
                       trySend(btState)
                   }
               }
           }
       }

       val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
       context.registerReceiver(receiver, filter)

       trySend(_bluetoothState.value)

       awaitClose { context.unregisterReceiver(receiver) }
    }

    private fun updateInitialState() {
       val adapter = getAdapter()
       _bluetoothState.value = when {
           adapter == null -> BluetoothState.UNAVAILABLE
           adapter.isEnabled -> BluetoothState.ON
           else -> BluetoothState.OFF
       }
       checkPermissions()
    }

    private fun registerReceiver() {
       receiver = object : BroadcastReceiver() {
           override fun onReceive(ctx: Context, intent: Intent) {
               when (intent.action) {
                   BluetoothAdapter.ACTION_STATE_CHANGED -> {
                       val state = intent.getIntExtra(
                           BluetoothAdapter.EXTRA_STATE,
                           BluetoothAdapter.ERROR
                       )
                       _bluetoothState.value = when (state) {
                           BluetoothAdapter.STATE_ON -> BluetoothState.ON
                           BluetoothAdapter.STATE_OFF -> BluetoothState.OFF
                           BluetoothAdapter.STATE_TURNING_ON -> BluetoothState.TURNING_ON
                           BluetoothAdapter.STATE_TURNING_OFF -> BluetoothState.TURNING_OFF
                           else -> BluetoothState.UNAVAILABLE
                       }
                   }
               }
           }
       }
       context.registerReceiver(receiver!!, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))
    }
}
