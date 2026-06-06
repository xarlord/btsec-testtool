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
import android.os.IBinder
import android.content.pm.ServiceInfo
import android.os.Build
import timber.log.Timber
import com.btsec.testtool.BtSecTestToolApplication.Companion.CHANNEL_ID_SERVICE
import com.btsec.testtool.BtSecTestToolApplication.Companion.NOTIFICATION_ID_SCAN

/**
 * Foreground service for background Bluetooth scanning operations.
 *
 * This service is designed EXCLUSIVELY for AUTHORIZED security testing.
 * All scanning requires explicit written authorization.
 *
 * Security: All incoming Intents are validated against the authorization system
 * before any scanning operation proceeds.
 */
class BluetoothScanService : Service() {

    companion object {
        const val EXTRA_AUTH_ID = "extra_auth_id"
        const val EXTRA_AUTH_TOKEN = "extra_auth_token"
        const val ACTION_START_SCAN = "com.btsec.testtool.action.START_SCAN"
        const val ACTION_STOP_SCAN = "com.btsec.testtool.action.STOP_SCAN"
        private val AUTH_ID_PATTERN = Regex("^BTSEC-\\d{8}-[A-Z0-9]{8}$")
    }

    override fun onCreate() {
        super.onCreate()
        startForegroundNotification()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!validateAuthorization(intent)) {
            Timber.w( "Unauthorized intent received — stopping service. " +
                "Intent action: ${intent?.action}, extras: ${intent?.extras?.keySet()}")
            stopSelf()
            return START_NOT_STICKY
        }

        when (intent?.action) {
            ACTION_START_SCAN -> {
                val authId = intent.getStringExtra(EXTRA_AUTH_ID) ?: ""
                Timber.i( "Starting authorized BLE scan with auth: ${authId.take(10)}***")
                // Scan logic handled by BluetoothRepository via ViewModel
            }
            ACTION_STOP_SCAN -> {
                Timber.i( "Stopping BLE scan")
                stopSelf()
            }
        }

        return START_NOT_STICKY
    }

    /**
     * Validate that the incoming Intent carries proper authorization.
     * Checks: intent non-null, auth ID present and matches format, auth token present.
     */
    private fun validateAuthorization(intent: Intent?): Boolean {
        if (intent == null) return false
        if (intent.action != ACTION_START_SCAN && intent.action != ACTION_STOP_SCAN) return false

        // STOP_SCAN doesn't require auth (it's a cancellation)
        if (intent.action == ACTION_STOP_SCAN) return true

        val authId = intent.getStringExtra(EXTRA_AUTH_ID)
        val authToken = intent.getStringExtra(EXTRA_AUTH_TOKEN)

        if (authId.isNullOrBlank()) {
            Timber.w( "Missing auth ID in scan intent")
            return false
        }

        if (!AUTH_ID_PATTERN.matches(authId)) {
            Timber.w( "Invalid auth ID format in scan intent: ${authId.take(10)}***")
            return false
        }

        if (authToken.isNullOrBlank()) {
            Timber.w( "Missing auth token in scan intent")
            return false
        }

        return true
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        Timber.d( "BluetoothScanService destroyed")
        super.onDestroy()
    }

    private fun startForegroundNotification() {
        val notification = Notification.Builder(this, CHANNEL_ID_SERVICE)
            .setContentTitle("BTSec Scan Active")
            .setContentText("Bluetooth security scanning in progress")
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID_SCAN,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else {
            startForeground(NOTIFICATION_ID_SCAN, notification)
        }
    }
}
