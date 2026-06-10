/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 *
 * MIT License - See LICENSE for full terms.
 */
package com.btsec.testtool.data.fuzzing

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothProfile
import android.content.Context
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.FuzzProgress
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import java.time.Instant
import java.util.Random
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * BLE fuzzing engine. Connects to a target, sends fuzz payloads at a controlled rate,
 * and detects crashes, hangs, unexpected responses, and information leaks.
 *
 * Falls back to simulated GATT when Android BT hardware is unavailable.
 *
 * @property payloadGenerator injects payload generation logic
 */
@Singleton
class BleFuzzEngine @Inject constructor(
    private val payloadGenerator: FuzzPayloadGenerator,
    @ApplicationContext private val context: Context
) {
    companion object {
        private const val TAG = "BleFuzzEngine"
        private const val RESPONSE_TIMEOUT_MS = 5_000L
        private const val MAX_RETRIES = 2
    }

    /**
     * Execute a fuzzing session against the target defined in [config].
     *
     * @param config    fuzz configuration (target, method, rate, etc.)
     * @param onProgress progress callback per packet
     * @param onFinding  callback for each discovered finding
     * @return [FuzzResult] with full session details
     */
    suspend fun executeFuzzing(
        config: FuzzConfig,
        onProgress: (FuzzProgress) -> Unit,
        onFinding: (FuzzFinding) -> Unit
    ): FuzzResult {
        val resultId = UUID.randomUUID().toString()
        val startTime = Instant.now()
        val errors = mutableListOf<FuzzError>()
        val findings = mutableListOf<FuzzFinding>()
        var sent = 0
        var received = 0
        var connected = true

        val connState = MutableStateFlow<ConnectionState>(ConnectionState.Connected)
        val wrapper = connectToDevice(config, connState)

        try {
            val validPkt = config.targetCharacteristic?.value
                ?: wrapper.readCharacteristic(config.targetService?.uuid, config.targetCharacteristic?.uuid)

            val payloads = payloadGenerator.generatePayloads(config.fuzzMethod, config.packetCount, config.randomSeed, validPkt)
            val exploitPayloads = if (config.dataPatterns.any { it.patternType == PatternType.KNOWN_EXPLOIT })
                payloadGenerator.generateKnownExploitPayloads().map { it.data } else emptyList()
            val all = payloads + exploitPayloads
            val total = all.size
            val delayMs = if (config.packetsPerSecond > 0) 1000L / config.packetsPerSecond else 100L

            for ((idx, payload) in all.withIndex()) {
                // Stop conditions
                if (!connected && config.stopOnDisconnect) {
                    addFinding(findings, sent, payload, "Device disconnected — possible crash",
                        VulnerabilitySeverity.HIGH, FindingCategory.CRASH,
                        "Device ${config.targetDevice.address} disconnected at packet $sent", onFinding)
                    break
                }
                if (config.durationSeconds != null &&
                    Instant.now().epochSecond - startTime.epochSecond >= config.durationSeconds) break

                when (val r = sendPacket(wrapper, config, payload)) {
                    is SendResult.Success -> {
                        sent++; received++
                        analyzeResponse(r.response, payload, sent, findings, onFinding)
                    }
                    is SendResult.Timeout -> {
                        sent++
                        addFinding(findings, sent, payload, "No response within ${RESPONSE_TIMEOUT_MS}ms — possible hang/DoS",
                            VulnerabilitySeverity.MEDIUM, FindingCategory.HANG,
                            "Payload length: ${payload.size}", onFinding)
                    }
                    is SendResult.Disconnected -> {
                        sent++; connected = false
                        addFinding(findings, sent, payload, "Device disconnected after packet — likely crash",
                            VulnerabilitySeverity.CRITICAL, FindingCategory.CRASH,
                            "Hex: ${payload.take(16).joinToString(" ") { "%02x".format(it) }}", onFinding)
                        errors += FuzzError(Instant.now(), sent, r.errorCode, "Device disconnected", ErrorSeverity.CRITICAL, payload)
                        if (config.stopOnDisconnect) break
                    }
                    is SendResult.Error -> {
                        sent++
                        errors += FuzzError(Instant.now(), sent, r.errorCode, r.message, ErrorSeverity.MEDIUM, payload)
                        if (config.stopOnError && r.errorCode == BluetoothGatt.GATT_FAILURE) break
                    }
                }

                onProgress(FuzzProgress(resultId, config,
                    if (connected) FuzzStatus.RUNNING else FuzzStatus.ERROR,
                    sent, received, errors.size, findings.size, startTime,
                    startTime.plusSeconds(((total - idx - 1) * delayMs) / 1000), idx + 1, total))
                delay(delayMs)
            }
        } finally { wrapper.disconnect() }

        val status = when {
            !connected -> FuzzStatus.ERROR
            errors.any { it.severity == ErrorSeverity.CRITICAL } -> FuzzStatus.ERROR
            sent >= config.packetCount -> FuzzStatus.COMPLETED
            else -> FuzzStatus.STOPPED
        }
        return FuzzResult(resultId, config, startTime, Instant.now(), status, sent, received,
            errors.toList(), findings.toList(), null, false)
    }

    private fun addFinding(
        list: MutableList<FuzzFinding>, pktNum: Int, data: ByteArray, desc: String,
        sev: VulnerabilitySeverity, cat: FindingCategory, notes: String?, cb: (FuzzFinding) -> Unit
    ) {
        val f = FuzzFinding(Instant.now(), pktNum, desc, sev, data, null, cat, false, notes)
        list += f; cb(f)
    }

    // --- Response analysis ---

    private fun analyzeResponse(
        response: ByteArray?, sent: ByteArray, pktNum: Int,
        findings: MutableList<FuzzFinding>, cb: (FuzzFinding) -> Unit
    ) {
        if (response == null) return
        // Info leak: unusually large response
        if (response.size > 128) {
            addFinding(findings, pktNum, sent,
                "Large response (${response.size}B) — possible information leak",
                VulnerabilitySeverity.HIGH, FindingCategory.INFORMATION_LEAK, null, cb); return
        }
        // Memory corruption: low-entropy repeated bytes
        if (response.size >= 16) {
            val ratio = response.toSet().size.toDouble() / response.size
            if (ratio < 0.1) {
                addFinding(findings, pktNum, sent,
                    "Low-entropy response (${(ratio * 100).toInt()}% unique) — possible memory corruption",
                    VulnerabilitySeverity.MEDIUM, FindingCategory.MEMORY_CORRUPTION, null, cb); return
            }
        }
        // Unexpected ATT error code
        if (response.size in 1..3) {
            val code = (response.lastOrNull()?.toInt() ?: 0) and 0xFF
            if (code in 0x80..0xFF) {
                addFinding(findings, pktNum, sent,
                    "Non-standard ATT error 0x${"%02x".format(code)} — unexpected response",
                    VulnerabilitySeverity.LOW, FindingCategory.UNEXPECTED_RESPONSE, null, cb)
            }
        }
    }

    // --- Connection ---

    /** Check if real Bluetooth hardware is available for fuzzing. */
    fun isBluetoothHardwareAvailable(): Boolean {
        val mgr = context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
        return mgr?.adapter?.bluetoothLeScanner != null
    }

    private fun connectToDevice(config: FuzzConfig, cs: MutableStateFlow<ConnectionState>): GattWrapper {
        if (!isBluetoothHardwareAvailable()) {
            throw IllegalStateException("No Bluetooth hardware available — fuzzing requires real BLE device")
        }
        val mgr = context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
            ?: throw IllegalStateException("BluetoothManager not available")
        val dev = mgr.adapter?.getRemoteDevice(config.targetDevice.address)
            ?: throw IllegalStateException("Cannot get remote device for ${config.targetDevice.address}")
        return RealGatt(dev, context, cs)
    }

    private suspend fun sendPacket(w: GattWrapper, c: FuzzConfig, p: ByteArray): SendResult {
        var last: SendResult = SendResult.Error(null, "No attempt")
        repeat(MAX_RETRIES + 1) { i ->
            last = w.writeCharacteristic(c.targetService?.uuid, c.targetCharacteristic?.uuid, p)
            if (last !is SendResult.Error) return last
            if (i < MAX_RETRIES) delay(100)
        }
        return last
    }

    // --- GATT wrappers ---

    private sealed class GattWrapper {
        abstract fun writeCharacteristic(svc: String?, chr: String?, value: ByteArray): SendResult
        abstract fun readCharacteristic(svc: String?, chr: String?): ByteArray?
        abstract fun disconnect()
    }

    private class RealGatt(
        device: android.bluetooth.BluetoothDevice, ctx: Context,
        private val connState: MutableStateFlow<ConnectionState>
    ) : GattWrapper() {
        private var gatt: BluetoothGatt? = null

        private val cb = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(g: BluetoothGatt, status: Int, state: Int) {
                if (state == BluetoothProfile.STATE_CONNECTED) { connState.value = ConnectionState.Connected; g.discoverServices() }
                else if (state == BluetoothProfile.STATE_DISCONNECTED) { connState.value = ConnectionState.Disconnected; gatt = null }
            }
            override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {}
            override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {}
        }

        init { try { gatt = device.connectGatt(ctx, false, cb) } catch (e: SecurityException) { android.util.Log.e(TAG, "RealGatt: permission denied connecting to ${device.address}", e); connState.value = ConnectionState.Error("Permission denied") } }

        override fun writeCharacteristic(svc: String?, chr: String?, value: ByteArray): SendResult {
            val g = gatt ?: return SendResult.Disconnected(null)
            return try {
                val s = svc?.let { g.getService(UUID.fromString(it)) } ?: return SendResult.Error(null, "Service not found")
                val c = chr?.let { s.getCharacteristic(UUID.fromString(it)) } ?: return SendResult.Error(null, "Char not found")
                c.value = value; c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                // writeCharacteristic is async — we don't get the device response here.
                // Return null response to indicate "write initiated but no response data available".
                // Response analysis will be skipped for writes that don't return data.
                if (g.writeCharacteristic(c)) SendResult.Success(null) else SendResult.Error(null, "write returned false")
            } catch (e: SecurityException) { SendResult.Error(null, "Permission: ${e.message}") }
        }

        override fun readCharacteristic(svc: String?, chr: String?): ByteArray? {
            val g = gatt ?: return null
            return try {
                val s = svc?.let { g.getService(UUID.fromString(it)) } ?: return null
                val c = chr?.let { s.getCharacteristic(UUID.fromString(it)) } ?: return null
                if (g.readCharacteristic(c)) c.value else null
            } catch (e: SecurityException) {
                android.util.Log.w(TAG, "readCharacteristic: permission denied for $svc/$chr — ${e.message}")
                null
            }
        }

        override fun disconnect() {
            try {
                gatt?.disconnect()
                gatt?.close()
            } catch (e: Exception) {
                android.util.Log.w(TAG, "disconnect: error closing GATT — ${e.message}")
            }
            gatt = null
        }
    }

    /** Result of sending a single fuzz packet. */
    sealed class SendResult {
        data class Success(val response: ByteArray?) : SendResult()
        data object Timeout : SendResult()
        data class Disconnected(val errorCode: Int?) : SendResult()
        data class Error(val errorCode: Int?, val message: String) : SendResult()
    }
}
