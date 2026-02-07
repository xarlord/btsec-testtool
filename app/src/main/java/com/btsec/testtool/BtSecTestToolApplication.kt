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
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import androidx.hilt.work.HiltAndroidApp
import androidx.work.Configuration
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import timber.log.Timber
import javax.inject.Inject

/**
 * Main Application class for BTSec Test Tool.
 *
 * This application is designed EXCLUSIVELY for AUTHORIZED security testing.
 * All testing requires explicit written authorization and is logged for audit.
 */
@HiltAndroidApp
class BtSecTestToolApplication : Application() {

    // Application scope for coroutines
    val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Inject
    lateinit var notificationManager: NotificationManager

    override fun onCreate() {
        super.onCreate()

        // Initialize Timber logging (only in debug builds)
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }

        // Create notification channels
        createNotificationChannels()

        Timber.d("BTSec Test Tool initialized")
        Timber.d("Version: ${BuildConfig.VERSION_NAME}")
        val buildType = if (BuildConfig.DEBUG) "DEBUG" else "RELEASE"
        Timber.d("Build: $buildType")
        Timber.d("Environment: ${BuildConfig.ENVIRONMENT}")
    }

    /**
     * Create notification channels for Android O+.
     */
    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Main notification channel
            val mainChannel = NotificationChannel(
                CHANNEL_ID_MAIN,
                "Main Notifications",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Main application notifications"
                setShowBadge(false)
            }

            // Foreground service channel
            val serviceChannel = NotificationChannel(
                CHANNEL_ID_SERVICE,
                "Background Services",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Background service notifications for scanning"
                setShowBadge(false)
                setSound(null)
            }

            // Testing notifications channel
            val testingChannel = NotificationChannel(
                CHANNEL_ID_TESTING,
                "Testing Notifications",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifications for testing activities"
                setShowBadge(true)
                enableVibration(true)
                enableLights(true)
            }

            notificationManager.createNotificationChannel(mainChannel)
            notificationManager.createNotificationChannel(serviceChannel)
            notificationManager.createNotificationChannel(testingChannel)
        }
    }

    override fun onTerminate() {
        super.onTerminate()
        Timber.d("BTSec Test Tool terminated")
    }

    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        Timber.d("Configuration changed")
    }

    companion object {
        const val CHANNEL_ID_MAIN = "channel_main"
        const val CHANNEL_ID_SERVICE = "channel_service"
        const val CHANNEL_ID_TESTING = "channel_testing"

        const val NOTIFICATION_ID_SCAN = 1001
        const val NOTIFICATION_ID_FUZZ = 1002
    }
}
