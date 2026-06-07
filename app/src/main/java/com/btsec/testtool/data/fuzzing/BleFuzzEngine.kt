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
        val counters = FuzzCounters()
        val connState = MutableStateFlow<ConnectionState>(ConnectionState.Connected)
        val wrapper = connectToDevice(config, connState)

        try {
            val payloads = preparePayloads(config, wrapper)
            sendAllPayloads(config, payloads, wrapper, counters, errors, findings, resultId, startTime, onProgress, onFinding)
        } finally { wrapper.disconnect() }

        val status = determineStatus(counters, errors, config)
        return FuzzResult(resultId, config, startTime, Instant.now(), status, counters.sent,
            counters.received, errors.toList(), findings.toList(), null, false)
    }

    private suspend fun preparePayloads(config: FuzzConfig, wrapper: GattWrapper): List<ByteArray> {
        val validPkt = config.targetCharacteristic?.value
            ?: wrapper.readCharacteristic(config.targetService?.uuid, config.targetCharacteristic?.uuid)
        val payloads = payloadGenerator.generatePayloads(config.fuzzMethod, config.packetCount, config.randomSeed, validPkt)
        val exploitPayloads = if (config.dataPatterns.any { it.patternType == PatternType.KNOWN_EXPLOIT })
            payloadGenerator.generateKnownExploitPayloads().map { it.data } else emptyList()
        return payloads + exploitPayloads
    }

    private suspend fun sendAllPayloads(
        config: FuzzConfig, payloads: List<ByteArray>, wrapper: GattWrapper,
        counters: FuzzCounters, errors: MutableList<FuzzError>,
        findings: MutableList<FuzzFinding>, resultId: String, startTime: Instant,
        onProgress: (FuzzProgress) -> Unit, onFinding: (FuzzFinding) -> Unit
    ) {
        var connected = true
        val delayMs = if (config.packetsPerSecond > 0) 1000L / config.packetsPerSecond else 100L
        val total = payloads.size

        for ((idx, payload) in payloads.withIndex()) {
            if (!connected && config.stopOnDisconnect) break
            if (config.durationSeconds != null &&
                Instant.now().epochSecond - startTime.epochSecond >= config.durationSeconds) break

            connected = processPacket(config, wrapper, payload, counters, errors, findings, connected, onFinding)
            reportProgress(onProgress, resultId, config, connected, counters, errors, findings, startTime, delayMs, idx, total)
            delay(delayMs)
        }
    }

    private suspend fun processPacket(
        config: FuzzConfig, wrapper: GattWrapper, payload: ByteArray,
        counters: FuzzCounters, errors: MutableList<FuzzError>,
        findings: MutableList<FuzzFinding>, connected: Boolean,
        onFinding: (FuzzFinding) -> Unit
    ): Boolean {
        var stillConnected = connected
        when (val r = sendPacket(wrapper, config, payload)) {
            is SendResult.Success -> {
                counters.sent++; counters.received++
                analyzeResponse(r.response, payload, counters.sent, findings, onFinding)
            }
            is SendResult.Timeout -> {
                counters.sent++
                addFinding(findings, counters.sent, payload, "No response within ${RESPONSE_TIMEOUT_MS}ms — possible hang/DoS",
                    VulnerabilitySeverity.MEDIUM, FindingCategory.HANG, "Payload length: ${payload.size}", onFinding)
            }
            is SendResult.Disconnected -> {
                counters.sent++; stillConnected = false
                addFinding(findings, counters.sent, payload, "Device disconnected after packet — likely crash",
                    VulnerabilitySeverity.CRITICAL, FindingCategory.CRASH,
                    "Hex: ${payload.take(16).joinToString(" ") { "%02x".format(it) }}", onFinding)
                errors += FuzzError(Instant.now(), counters.sent, r.errorCode, "Device disconnected", ErrorSeverity.CRITICAL, payload)
                if (config.stopOnDisconnect) return stillConnected
            }
            is SendResult.Error -> {
                counters.sent++
                errors += FuzzError(Instant.now(), counters.sent, r.errorCode, r.message, ErrorSeverity.MEDIUM, payload)
                if (config.stopOnError && r.errorCode == BluetoothGatt.GATT_FAILURE) return stillConnected
            }
        }
        return stillConnected
    }

    private fun reportProgress(
        onProgress: (FuzzProgress) -> Unit, resultId: String, config: FuzzConfig,
        connected: Boolean, counters: FuzzCounters, errors: MutableList<FuzzError>,
        findings: MutableList<FuzzFinding>, startTime: Instant, delayMs: Long,
        idx: Int, total: Int
    ) {
        onProgress(FuzzProgress(resultId, config,
            if (connected) FuzzStatus.RUNNING else FuzzStatus.ERROR,
            counters.sent, counters.received, errors.size, findings.size, startTime,
            startTime.plusSeconds(((total - idx - 1) * delayMs) / 1000), idx + 1, total))
    }

    private fun determineStatus(counters: FuzzCounters, errors: List<FuzzError>, config: FuzzConfig): FuzzStatus {
        return when {
            errors.any { it.severity == ErrorSeverity.CRITICAL } -> FuzzStatus.ERROR
            counters.sent >= config.packetCount -> FuzzStatus.COMPLETED
            else -> FuzzStatus.STOPPED
        }
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
        checkInfoLeak(response, sent, pktNum, findings, cb)
        checkMemoryCorruption(response, sent, pktNum, findings, cb)
        checkUnexpectedAttError(response, sent, pktNum, findings, cb)
    }

    private fun checkInfoLeak(
        response: ByteArray, sent: ByteArray, pktNum: Int,
        findings: MutableList<FuzzFinding>, cb: (FuzzFinding) -> Unit
    ) {
        if (response.size > 128) {
            addFinding(findings, pktNum, sent,
                "Large response (${response.size}B) — possible information leak",
                VulnerabilitySeverity.HIGH, FindingCategory.INFORMATION_LEAK, null, cb)
        }
    }

    private fun checkMemoryCorruption(
        response: ByteArray, sent: ByteArray, pktNum: Int,
        findings: MutableList<FuzzFinding>, cb: (FuzzFinding) -> Unit
    ) {
        if (response.size >= 16) {
            val ratio = response.toSet().size.toDouble() / response.size
            if (ratio < 0.1) {
                addFinding(findings, pktNum, sent,
                    "Low-entropy response (${(ratio * 100).toInt()}% unique) — possible memory corruption",
                    VulnerabilitySeverity.MEDIUM, FindingCategory.MEMORY_CORRUPTION, null, cb)
            }
        }
    }

    private fun checkUnexpectedAttError(
        response: ByteArray, sent: ByteArray, pktNum: Int,
        findings: MutableList<FuzzFinding>, cb: (FuzzFinding) -> Unit
    ) {
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

    private fun connectToDevice(config: FuzzConfig, cs: MutableStateFlow<ConnectionState>): GattWrapper = try {
        val mgr = context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
        val dev = mgr?.adapter?.getRemoteDevice(config.targetDevice.address)
        if (dev != null) RealGatt(dev, context, cs) else SimGatt(cs)
    } catch (_: Exception) { SimGatt(cs) }

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

        init { try { gatt = device.connectGatt(ctx, false, cb) } catch (_: SecurityException) { connState.value = ConnectionState.Error("Permission denied") } }

        override fun writeCharacteristic(svc: String?, chr: String?, value: ByteArray): SendResult {
            val g = gatt ?: return SendResult.Disconnected(null)
            return try {
                val s = svc?.let { g.getService(UUID.fromString(it)) } ?: return SendResult.Error(null, "Service not found")
                val c = chr?.let { s.getCharacteristic(UUID.fromString(it)) } ?: return SendResult.Error(null, "Char not found")
                c.value = value; c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                if (g.writeCharacteristic(c)) SendResult.Success(value) else SendResult.Error(null, "write returned false")
            } catch (e: SecurityException) { SendResult.Error(null, "Permission: ${e.message}") }
        }

        override fun readCharacteristic(svc: String?, chr: String?): ByteArray? {
            val g = gatt ?: return null
            return try {
                val s = svc?.let { g.getService(UUID.fromString(it)) } ?: return null
                val c = chr?.let { s.getCharacteristic(UUID.fromString(it)) } ?: return null
                if (g.readCharacteristic(c)) c.value else null
            } catch (_: SecurityException) { null }
        }

        override fun disconnect() {
            try { gatt?.disconnect(); gatt?.close() } catch (_: Exception) {}
            gatt = null
        }
    }

    /** Simulated GATT for testing without real hardware. */
    private class SimGatt(private val connState: MutableStateFlow<ConnectionState>) : GattWrapper() {
        private var disconnected = false

        override fun writeCharacteristic(svc: String?, chr: String?, value: ByteArray): SendResult {
            if (disconnected) return SendResult.Disconnected(null)
            connState.value = ConnectionState.Connected
            if (value.size > 512) { disconnected = true; connState.value = ConnectionState.Disconnected; return SendResult.Disconnected(null) }
            val s = String(value, Charsets.UTF_8)
            if (s.contains("%n") && s.count { it == '%' } > 8) return SendResult.Timeout
            return SendResult.Success(value.copyOfRange(0, minOf(value.size, 20)))
        }
        override fun readCharacteristic(svc: String?, chr: String?) = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        override fun disconnect() { disconnected = true; connState.value = ConnectionState.Disconnected }
    }

    /** Result of sending a single fuzz packet. */
    sealed class SendResult {
        data class Success(val response: ByteArray?) : SendResult()
        data object Timeout : SendResult()
        data class Disconnected(val errorCode: Int?) : SendResult()
        data class Error(val errorCode: Int?, val message: String) : SendResult()
    }

    /** Mutable counters for tracking fuzzing progress. */
    private class FuzzCounters {
        var sent: Int = 0
        var received: Int = 0
    }
}
