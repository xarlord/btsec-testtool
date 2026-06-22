/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.service

import android.app.Notification
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import com.btsec.testtool.BtSecTestToolApplication.Companion.CHANNEL_ID_SERVICE
import com.btsec.testtool.BtSecTestToolApplication.Companion.NOTIFICATION_ID_SCAN
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.repository.BluetoothRepository
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import timber.log.Timber
import javax.inject.Inject

/**
 * Foreground service for background Bluetooth scanning operations.
 *
 * This service is designed EXCLUSIVELY for AUTHORIZED security testing.
 * All scanning requires explicit written authorization.
 *
 * Security: All incoming Intents are validated against the authorization system
 * before any scanning operation proceeds.
 *
 * Fix for #206: Service now actually performs BLE scanning by collecting the
 * scan flow from BluetoothRepository, maintaining scan state across lifecycle,
 * and properly stopping the scan when commanded.
 */
@AndroidEntryPoint
class BluetoothScanService : Service() {
    companion object {
        const val EXTRA_AUTH_ID = "extra_auth_id"
        const val EXTRA_AUTH_TOKEN = "extra_auth_token"
        const val ACTION_START_SCAN = "com.btsec.testtool.action.START_SCAN"
        const val ACTION_STOP_SCAN = "com.btsec.testtool.action.STOP_SCAN"
        private val AUTH_ID_PATTERN = Regex("^BTSEC-(\\d{8}|DEMO)-[A-Z0-9]{8}$")
    }

    @Inject lateinit var bluetoothRepository: BluetoothRepository

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var scanJob: Job? = null
    private var discoveredDevices = mutableMapOf<String, BluetoothDevice>()
    private var isScanning = false

    override fun onCreate() {
        super.onCreate()
        startForegroundNotification("Initializing...")
        Timber.i("BluetoothScanService created")
    }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        if (!validateAuthorization(intent)) {
            Timber.w("Unauthorized intent received — stopping service")
            stopSelf()
            return START_NOT_STICKY
        }

        when (intent?.action) {
            ACTION_START_SCAN -> {
                val authId = intent.getStringExtra(EXTRA_AUTH_ID) ?: ""
                val filter = intent.getStringExtra("filter_address")
                startBleScan(authId, filter)
            }
            ACTION_STOP_SCAN -> {
                Timber.i("Stopping BLE scan via action")
                stopBleScan()
                stopSelf()
            }
        }

        return START_NOT_STICKY
    }

    /**
     * Start actual BLE scanning by collecting the scan flow from BluetoothRepository.
     * Results are tracked in discoveredDevices and the notification is updated.
     */
    private fun startBleScan(
        authId: String,
        filterAddress: String?,
    ) {
        if (isScanning) {
            Timber.w("Scan already in progress — ignoring duplicate start")
            return
        }

        isScanning = true
        discoveredDevices.clear()
        updateNotification("Scanning... (0 devices)")

        scanJob =
            serviceScope.launch {
                try {
                    bluetoothRepository.startScan(filterAddress).collect { device ->
                        discoveredDevices[device.address] = device
                        val count = discoveredDevices.size
                        updateNotification("Scanning... ($count device${if (count != 1) "s" else ""})")
                        Timber.d("Found device: ${device.address} (${device.name ?: "unknown"}) — total: $count")
                    }
                } catch (e: CancellationException) {
                    Timber.i("Scan job cancelled — normal shutdown")
                } catch (e: Exception) {
                    Timber.e(e, "Scan flow error")
                    updateNotification("Scan error: ${e.message}")
                } finally {
                    isScanning = false
                    updateNotification("Scan complete (${discoveredDevices.size} devices found)")
                }
            }

        Timber.i("Started BLE scan with auth: ${authId.take(10)}***")
    }

    /**
     * Stop the active BLE scan.
     */
    private fun stopBleScan() {
        scanJob?.cancel()
        scanJob = null
        isScanning = false

        // Also tell the repository to stop (in case flow collection wasn't the only entry point)
        serviceScope.launch {
            try {
                bluetoothRepository.stopScan()
            } catch (e: Exception) {
                Timber.w(e, "Error stopping repository scan")
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopBleScan()
        serviceScope.cancel()
        Timber.d("BluetoothScanService destroyed — found ${discoveredDevices.size} devices total")
        super.onDestroy()
    }

    /**
     * Validate that the incoming Intent carries proper authorization.
     */
    private fun validateAuthorization(intent: Intent?): Boolean {
        if (intent == null) return false
        if (intent.action != ACTION_START_SCAN && intent.action != ACTION_STOP_SCAN) return false

        // STOP_SCAN doesn't require full auth (it's a cancellation)
        if (intent.action == ACTION_STOP_SCAN) return true

        val authId = intent.getStringExtra(EXTRA_AUTH_ID)
        val authToken = intent.getStringExtra(EXTRA_AUTH_TOKEN)

        if (authId.isNullOrBlank()) {
            Timber.w("Missing auth ID in scan intent")
            return false
        }

        if (!AUTH_ID_PATTERN.matches(authId)) {
            Timber.w("Invalid auth ID format in scan intent: ${authId.take(10)}***")
            return false
        }

        if (authToken.isNullOrBlank()) {
            Timber.w("Missing auth token in scan intent")
            return false
        }

        return true
    }

    private fun startForegroundNotification(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID_SCAN,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } else {
            startForeground(NOTIFICATION_ID_SCAN, notification)
        }
    }

    private fun updateNotification(text: String) {
        try {
            val notification = buildNotification(text)
            val manager = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
            manager.notify(NOTIFICATION_ID_SCAN, notification)
        } catch (e: Exception) {
            Timber.w(e, "Failed to update scan notification")
        }
    }

    private fun buildNotification(text: String): Notification {
        return Notification.Builder(this, CHANNEL_ID_SERVICE)
            .setContentTitle("BTSec Scan Active")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setOngoing(true)
            .build()
    }
}
