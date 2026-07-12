/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.keyextraction

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.UUID
import kotlin.coroutines.resume

/**
 * Real BLE implementation of [KeyExtractionProbe].
 *
 * Connects to a BLE device and attempts to negotiate low-entropy encryption
 * keys via the KNOB attack vector. This implementation uses Android's BLE APIs
 * to establish GATT connections and observe encryption negotiation.
 *
 * NOTE: Full KNOB attack requires modifying the LMP key size field during
 * pairing, which is not directly exposed by the Android SDK. This implementation
 * performs the best-effort probing available via public APIs and will return
 * [KeyNegotiationResult.Unavailable] on most stock Android devices.
 *
 * This is for AUTHORIZED security testing only.
 */
@SuppressLint("MissingPermission")
@TargetApi(Build.VERSION_CODES.LOLLIPOP)
class BleKeyExtractionProbe(
    private val context: Context,
    private val deviceAddress: String,
) : KeyExtractionProbe {
    private var gatt: BluetoothGatt? = null
    private var cachedEncryptionInfo: EncryptionInfo? = null

    override suspend fun negotiateKeySize(keySizeBytes: Int): KeyNegotiationResult {
        // The Android BLE stack does not expose direct control over the
        // encryption key size negotiation at the LMP level. A full KNOB
        // attack requires a modified BLE controller or custom firmware.
        // On stock Android, we return Unavailable to indicate the platform
        // limitation honestly rather than fabricating results.
        //
        // When running on a rooted device with a custom BLE stack or with
        // HCI snoop logging enabled, a real implementation could:
        // 1. Intercept the LMP pairing request via HCI channel
        // 2. Modify the max_enc_key_size field to the target value
        // 3. Observe whether the remote device accepts or rejects
        return KeyNegotiationResult.Unavailable
    }

    override suspend fun readCharacteristic(
        serviceUuid: String,
        charUuid: String,
    ): ByteArray? {
        val gattConnection = ensureConnected() ?: return null
        return suspendCancellableCoroutine { cont ->
            val service =
                gattConnection.getService(UUID.fromString(serviceUuid)) ?: run {
                    cont.resume(null)
                    return@suspendCancellableCoroutine
                }
            val characteristic =
                service.getCharacteristic(UUID.fromString(charUuid)) ?: run {
                    cont.resume(null)
                    return@suspendCancellableCoroutine
                }
            val readResult = gattConnection.readCharacteristic(characteristic)
            if (!readResult) {
                cont.resume(null)
            }
            // In a full implementation, we'd wait for onCharacteristicRead callback.
            // For now, return null as the async callback path is not wired.
            cont.resume(null)
        }
    }

    override fun getEncryptionInfo(): EncryptionInfo? {
        return cachedEncryptionInfo
    }

    override fun isBonded(): Boolean {
        return try {
            val adapter =
                (
                    context.getSystemService(Context.BLUETOOTH_SERVICE)
                        as? android.bluetooth.BluetoothManager?
                )?.adapter
            val device = adapter?.getRemoteDevice(deviceAddress)
            device?.bondState == android.bluetooth.BluetoothDevice.BOND_BONDED
        } catch (_: SecurityException) {
            false
        }
    }

    override fun close() {
        try {
            gatt?.close()
        } catch (_: Exception) {
            // Ignore close errors
        }
        gatt = null
    }

    private suspend fun ensureConnected(): BluetoothGatt? {
        gatt?.let { return it }

        val adapter =
            (
                context.getSystemService(Context.BLUETOOTH_SERVICE)
                    as? android.bluetooth.BluetoothManager?
            )?.adapter ?: return null
        val device = adapter.getRemoteDevice(deviceAddress) ?: return null

        return suspendCancellableCoroutine { cont ->
            val callback =
                object : BluetoothGattCallback() {
                    override fun onConnectionStateChange(
                        gatt: BluetoothGatt,
                        status: Int,
                        newState: Int,
                    ) {
                        if (newState == BluetoothProfile.STATE_CONNECTED) {
                            this@BleKeyExtractionProbe.gatt = gatt
                            cont.resume(gatt)
                        } else {
                            gatt.close()
                            cont.resume(null)
                        }
                    }
                }
            val connected = device.connectGatt(context, false, callback)
            if (connected == null) {
                cont.resume(null)
            }
        }
    }
}
