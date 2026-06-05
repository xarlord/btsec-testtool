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
import com.btsec.testtool.BtSecTestToolApplication.Companion.CHANNEL_ID_SERVICE
import com.btsec.testtool.BtSecTestToolApplication.Companion.NOTIFICATION_ID_SCAN

/**
 * Foreground service for background Bluetooth scanning operations.
 *
 * This service is designed EXCLUSIVELY for AUTHORIZED security testing.
 * All scanning requires explicit written authorization.
 */
class BluetoothScanService : Service() {

    override fun onCreate() {
        super.onCreate()
        startForegroundNotification()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
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
