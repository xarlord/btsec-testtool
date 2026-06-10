/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.GattCharacteristicConfig
import com.btsec.testtool.domain.model.GattDescriptorConfig
import com.btsec.testtool.domain.model.GattServerEvent
import com.btsec.testtool.domain.model.GattServerEventType
import com.btsec.testtool.domain.model.GattServerPreset
import com.btsec.testtool.domain.model.GattServerPresetCategory
import com.btsec.testtool.domain.model.GattServerSession
import com.btsec.testtool.domain.model.GattServiceConfig
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for GATT Server Emulator.
 *
 * Provides predefined BLE peripheral profiles (presets) for testing
 * how tools and devices interact with a controlled GATT server.
 *
 * All testing must be performed on AUTHORIZED devices with proper consent.
 */
@Singleton
class GattServerUseCase @Inject constructor() {

    companion object {
        // Standard BLE service UUIDs
        const val UUID_HEART_RATE = "0000180d-0000-1000-8000-00805f9b34fb"
        const val UUID_BATTERY = "0000180f-0000-1000-8000-00805f9b34fb"
        const val UUID_HEALTH_THERMOMETER = "00001809-0000-1000-8000-00805f9b34fb"
        const val UUID_GENERIC_ACCESS = "00001800-0000-1000-8000-00805f9b34fb"
        const val UUID_GENERIC_ATTRIBUTE = "00001801-0000-1000-8000-00805f9b34fb"

        // Heart Rate characteristics
        const val UUID_HR_MEASUREMENT = "00002a37-0000-1000-8000-00805f9b34fb"
        const val UUID_BODY_SENSOR_LOCATION = "00002a38-0000-1000-8000-00805f9b34fb"
        const val UUID_HR_CONTROL_POINT = "00002a39-0000-1000-8000-00805f9b34fb"

        // Battery characteristics
        const val UUID_BATTERY_LEVEL = "00002a19-0000-1000-8000-00805f9b34fb"

        // Thermometer characteristics
        const val UUID_TEMP_MEASUREMENT = "00002a1c-0000-1000-8000-00805f9b34fb"
        const val UUID_TEMP_TYPE = "00002a1d-0000-1000-8000-00805f9b34fb"

        // Custom vulnerable service UUID
        const val UUID_VULNERABLE_SERVICE = "0000deed-0000-1000-8000-00805f9b34fb"
        const val UUID_READ_WRITE_NO_AUTH = "0000beef-0000-1000-8000-00805f9b34fb"
        const val UUID_ADMIN_CHAR = "0000cafe-0000-1000-8000-00805f9b34fb"
        const val UUID_SENSITIVE_DATA = "0000dead-0000-1000-8000-00805f9b34fb"

        // Client Characteristic Configuration Descriptor
        const val UUID_CCCD = "00002902-0000-1000-8000-00805f9b34fb"

        // BluetoothGattCharacteristic property flags
        const val PROPERTY_READ = 0x02
        const val PROPERTY_WRITE = 0x08
        const val PROPERTY_NOTIFY = 0x10
        const val PROPERTY_INDICATE = 0x20

        // BluetoothGattCharacteristic permission flags
        const val PERMISSION_READ = 0x01
        const val PERMISSION_WRITE = 0x10

        // BluetoothGattService types
        const val SERVICE_TYPE_PRIMARY = 0
        const val SERVICE_TYPE_SECONDARY = 1

        // BluetoothGatt status codes
        const val GATT_SUCCESS = 0
        const val GATT_FAILURE = 0x101

        // Simulated credentials for vulnerable preset
        private const val SIMULATED_CREDENTIALS = "admin:password123"
    }

    /**
     * Returns all predefined GATT server presets.
     */
    fun getPresets(): List<GattServerPreset> {
        return listOf(
            buildHeartRatePreset(),
            buildThermometerPreset(),
            buildGenericAccessPreset(),
            buildVulnerablePreset(),
            buildCustomPreset()
        )
    }

    /**
     * Heart Rate Monitor preset (HRM 180D + Battery 180F).
     */
    fun buildHeartRatePreset(): GattServerPreset {
        val heartRateChars = listOf(
            GattCharacteristicConfig(
                uuid = UUID_HR_MEASUREMENT,
                properties = PROPERTY_READ or PROPERTY_NOTIFY,
                permissions = PERMISSION_READ,
                initialValue = byteArrayOf(0x00, 0x48), // Flags=0, HR=72 bpm
                descriptors = listOf(
                    GattDescriptorConfig(
                        uuid = UUID_CCCD,
                        permissions = PERMISSION_READ or PERMISSION_WRITE,
                        initialValue = byteArrayOf(0x00, 0x00)
                    )
                )
            ),
            GattCharacteristicConfig(
                uuid = UUID_BODY_SENSOR_LOCATION,
                properties = PROPERTY_READ,
                permissions = PERMISSION_READ,
                initialValue = byteArrayOf(0x01) // Chest
            ),
            GattCharacteristicConfig(
                uuid = UUID_HR_CONTROL_POINT,
                properties = PROPERTY_WRITE,
                permissions = PERMISSION_WRITE,
                initialValue = byteArrayOf()
            )
        )

        val batteryChars = listOf(
            GattCharacteristicConfig(
                uuid = UUID_BATTERY_LEVEL,
                properties = PROPERTY_READ or PROPERTY_NOTIFY,
                permissions = PERMISSION_READ,
                initialValue = byteArrayOf(0x64), // 100%
                descriptors = listOf(
                    GattDescriptorConfig(
                        uuid = UUID_CCCD,
                        permissions = PERMISSION_READ or PERMISSION_WRITE,
                        initialValue = byteArrayOf(0x00, 0x00)
                    )
                )
            )
        )

        return GattServerPreset(
            name = "Heart Rate Monitor",
            description = "Emulates a standard heart rate monitor with battery service. Includes HR measurement (notify + read), body sensor location, HR control point, and battery level.",
            services = listOf(
                GattServiceConfig(UUID_HEART_RATE, SERVICE_TYPE_PRIMARY, heartRateChars),
                GattServiceConfig(UUID_BATTERY, SERVICE_TYPE_PRIMARY, batteryChars)
            ),
            category = GattServerPresetCategory.HEART_RATE
        )
    }

    /**
     * Health Thermometer preset (1809).
     */
    fun buildThermometerPreset(): GattServerPreset {
        val thermometerChars = listOf(
            GattCharacteristicConfig(
                uuid = UUID_TEMP_MEASUREMENT,
                properties = PROPERTY_INDICATE,
                permissions = PERMISSION_READ,
                initialValue = byteArrayOf(0x00, 0xE7.toByte(), 0x18.toByte(), 0x00, 0x00), // 36.7°C IEEE-11073
                descriptors = listOf(
                    GattDescriptorConfig(
                        uuid = UUID_CCCD,
                        permissions = PERMISSION_READ or PERMISSION_WRITE,
                        initialValue = byteArrayOf(0x00, 0x00)
                    )
                )
            ),
            GattCharacteristicConfig(
                uuid = UUID_TEMP_TYPE,
                properties = PROPERTY_READ,
                permissions = PERMISSION_READ,
                initialValue = byteArrayOf(0x01) // Armpit
            )
        )

        return GattServerPreset(
            name = "Health Thermometer",
            description = "Emulates a health thermometer with temperature measurement (indicate) and temperature type.",
            services = listOf(
                GattServiceConfig(UUID_HEALTH_THERMOMETER, SERVICE_TYPE_PRIMARY, thermometerChars)
            ),
            category = GattServerPresetCategory.THERMOMETER
        )
    }

    /**
     * Generic Access (1800) + Generic Attribute (1801) preset.
     */
    private fun buildGenericAccessPreset(): GattServerPreset {
        val genericAccessChars = listOf(
            GattCharacteristicConfig(
                uuid = "00002a00-0000-1000-8000-00805f9b34fb", // Device Name
                properties = PROPERTY_READ,
                permissions = PERMISSION_READ,
                initialValue = "BTSec-GATT".toByteArray()
            ),
            GattCharacteristicConfig(
                uuid = "00002a01-0000-1000-8000-00805f9b34fb", // Appearance
                properties = PROPERTY_READ,
                permissions = PERMISSION_READ,
                initialValue = byteArrayOf(0x00, 0x00) // Generic Unknown
            )
        )

        val genericAttributeChars = listOf(
            GattCharacteristicConfig(
                uuid = "00002a05-0000-1000-8000-00805f9b34fb", // Service Changed
                properties = PROPERTY_INDICATE,
                permissions = PERMISSION_READ,
                initialValue = byteArrayOf(),
                descriptors = listOf(
                    GattDescriptorConfig(
                        uuid = UUID_CCCD,
                        permissions = PERMISSION_READ or PERMISSION_WRITE,
                        initialValue = byteArrayOf(0x00, 0x00)
                    )
                )
            )
        )

        return GattServerPreset(
            name = "Generic Access + Attribute",
            description = "Standard Generic Access (1800) and Generic Attribute (1801) services for basic BLE device emulation.",
            services = listOf(
                GattServiceConfig(UUID_GENERIC_ACCESS, SERVICE_TYPE_PRIMARY, genericAccessChars),
                GattServiceConfig(UUID_GENERIC_ATTRIBUTE, SERVICE_TYPE_PRIMARY, genericAttributeChars)
            ),
            category = GattServerPresetCategory.BATTERY
        )
    }

    /**
     * Vulnerable Device preset — no auth required, allows unencrypted reads/writes.
     */
    fun buildVulnerablePreset(): GattServerPreset {
        val vulnerableChars = listOf(
            GattCharacteristicConfig(
                uuid = UUID_READ_WRITE_NO_AUTH,
                properties = PROPERTY_READ or PROPERTY_WRITE,
                permissions = PERMISSION_READ or PERMISSION_WRITE,
                initialValue = "open access".toByteArray()
            ),
            GattCharacteristicConfig(
                uuid = UUID_ADMIN_CHAR,
                properties = PROPERTY_READ or PROPERTY_WRITE,
                permissions = PERMISSION_READ or PERMISSION_WRITE,
                initialValue = "admin enabled".toByteArray()
            ),
            GattCharacteristicConfig(
                uuid = UUID_SENSITIVE_DATA,
                properties = PROPERTY_READ,
                permissions = PERMISSION_READ,
                initialValue = SIMULATED_CREDENTIALS.toByteArray()
            )
        )

        return GattServerPreset(
            name = "Vulnerable Device",
            description = "A deliberately insecure BLE device for testing. No authentication or encryption required. Includes read-write, admin, and sensitive data characteristics.",
            services = listOf(
                GattServiceConfig(UUID_VULNERABLE_SERVICE, SERVICE_TYPE_PRIMARY, vulnerableChars)
            ),
            category = GattServerPresetCategory.VULNERABLE
        )
    }

    /**
     * Custom preset — empty, user adds services.
     */
    private fun buildCustomPreset(): GattServerPreset {
        return GattServerPreset(
            name = "Custom Device",
            description = "An empty preset for building custom GATT server configurations.",
            services = emptyList(),
            category = GattServerPresetCategory.CUSTOM
        )
    }

    /**
     * Serialize service configs to JSON for storage.
     */
    fun buildServiceConfigs(configs: List<GattServiceConfig>): ByteArray {
        val jsonArray = JSONArray()
        for (service in configs) {
            jsonArray.put(serializeServiceConfig(service))
        }
        return jsonArray.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Deserialize service configs from JSON.
     */
    fun parseServiceConfigs(data: ByteArray): List<GattServiceConfig> {
        if (data.isEmpty()) return emptyList()
        val jsonString = String(data, Charsets.UTF_8)
        val jsonArray = JSONArray(jsonString)
        val result = mutableListOf<GattServiceConfig>()
        for (i in 0 until jsonArray.length()) {
            result.add(deserializeServiceConfig(jsonArray.getJSONObject(i)))
        }
        return result
    }

    /**
     * Return human-readable description of the event.
     */
    fun analyzeEvent(event: GattServerEvent): String {
        val sb = StringBuilder()
        val timeStr = formatDate(event.timestamp)

        sb.appendLine("[${event.eventType.name}] at $timeStr")

        when (event.eventType) {
            GattServerEventType.CONNECTION_STATE_CHANGED -> {
                sb.appendLine("  Device: ${event.deviceAddress ?: "unknown"}")
                val stateValue = event.value?.let { String(it, Charsets.UTF_8) } ?: "unknown"
                sb.appendLine("  State: $stateValue")
            }
            GattServerEventType.CHARACTERISTIC_READ_REQUEST -> {
                sb.appendLine("  Device: ${event.deviceAddress ?: "unknown"}")
                sb.appendLine("  Characteristic: ${event.characteristicUuid ?: "unknown"}")
                sb.appendLine("  Offset: ${event.offset}")
                event.response?.let { resp ->
                    sb.appendLine("  Response status: ${if (resp.status == GATT_SUCCESS) "SUCCESS" else "FAILURE (0x${resp.status.toString(16)})"}")
                    if (resp.delay > 0) sb.appendLine("  Simulated delay: ${resp.delay}ms")
                }
            }
            GattServerEventType.CHARACTERISTIC_WRITE_REQUEST -> {
                sb.appendLine("  Device: ${event.deviceAddress ?: "unknown"}")
                sb.appendLine("  Characteristic: ${event.characteristicUuid ?: "unknown"}")
                sb.appendLine("  Offset: ${event.offset}")
                event.value?.let { sb.appendLine("  Value (${it.size} bytes): ${it.toHexString()}") }
                event.response?.let { resp ->
                    sb.appendLine("  Response status: ${if (resp.status == GATT_SUCCESS) "SUCCESS" else "FAILURE"}")
                }
            }
            GattServerEventType.DESCRIPTOR_READ_REQUEST -> {
                sb.appendLine("  Device: ${event.deviceAddress ?: "unknown"}")
                sb.appendLine("  Descriptor: ${event.characteristicUuid ?: "unknown"}")
                sb.appendLine("  Offset: ${event.offset}")
            }
            GattServerEventType.DESCRIPTOR_WRITE_REQUEST -> {
                sb.appendLine("  Device: ${event.deviceAddress ?: "unknown"}")
                sb.appendLine("  Descriptor: ${event.characteristicUuid ?: "unknown"}")
                event.value?.let { sb.appendLine("  Value (${it.size} bytes): ${it.toHexString()}") }
            }
            GattServerEventType.NOTIFICATION_SENT -> {
                sb.appendLine("  Device: ${event.deviceAddress ?: "unknown"}")
                event.response?.let { resp ->
                    sb.appendLine("  Status: ${if (resp.status == GATT_SUCCESS) "SUCCESS" else "FAILURE"}")
                }
            }
            GattServerEventType.MTU_CHANGED -> {
                sb.appendLine("  Device: ${event.deviceAddress ?: "unknown"}")
                event.value?.let { sb.appendLine("  New MTU: ${it.size}") }
            }
            GattServerEventType.SERVICE_ADDED -> {
                event.response?.let { resp ->
                    sb.appendLine("  Status: ${if (resp.status == GATT_SUCCESS) "SUCCESS" else "FAILURE"}")
                }
                sb.appendLine("  Service added successfully")
            }
        }
        return sb.toString().trimEnd()
    }

    /**
     * Generate a text report of the server session.
     */
    fun generateSessionReport(session: GattServerSession): String {
        val sb = StringBuilder()
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine("  GATT Server Session Report")
        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine()
        sb.appendLine("Session ID:    ${session.id}")
        sb.appendLine("Start Time:    ${dateFormat.format(Date(session.startTime))}")
        session.endTime?.let {
            sb.appendLine("End Time:      ${dateFormat.format(Date(it))}")
            val durationSec = (it - session.startTime) / 1000.0
            sb.appendLine("Duration:      ${"%.1f".format(durationSec)}s")
        } ?: sb.appendLine("End Time:      (active)")
        sb.appendLine()

        session.preset?.let {
            sb.appendLine("Preset:        ${it.name}")
            sb.appendLine("Description:   ${it.description}")
            sb.appendLine("Category:      ${it.category.name}")
        } ?: sb.appendLine("Preset:        (none)")
        sb.appendLine()

        sb.appendLine("─── Statistics ───")
        sb.appendLine("Total Read Requests:    ${session.totalReadRequests}")
        sb.appendLine("Total Write Requests:   ${session.totalWriteRequests}")
        sb.appendLine("Total Connections:      ${session.totalConnections}")
        sb.appendLine("Connected Devices:      ${session.connectedDevices.size}")
        sb.appendLine("Total Events:           ${session.events.size}")
        sb.appendLine()

        if (session.connectedDevices.isNotEmpty()) {
            sb.appendLine("─── Connected Devices ───")
            session.connectedDevices.forEach { addr ->
                sb.appendLine("  - $addr")
            }
            sb.appendLine()
        }

        if (session.events.isNotEmpty()) {
            sb.appendLine("─── Recent Events (last 10) ───")
            session.events.takeLast(10).forEach { event ->
                sb.appendLine("  ${analyzeEvent(event).replace("\n", "\n  ")}")
            }
            sb.appendLine()
        }

        sb.appendLine("═══════════════════════════════════════════")
        return sb.toString()
    }

    // ── Serialization helpers ──

    private fun serializeServiceConfig(config: GattServiceConfig): JSONObject {
        val json = JSONObject()
        json.put("uuid", config.uuid)
        json.put("serviceType", config.serviceType)
        val charsArray = JSONArray()
        for (char in config.characteristics) {
            charsArray.put(serializeCharacteristicConfig(char))
        }
        json.put("characteristics", charsArray)
        return json
    }

    private fun serializeCharacteristicConfig(config: GattCharacteristicConfig): JSONObject {
        val json = JSONObject()
        json.put("uuid", config.uuid)
        json.put("properties", config.properties)
        json.put("permissions", config.permissions)
        json.put("initialValue", config.initialValue.toHexString())
        val descArray = JSONArray()
        for (desc in config.descriptors) {
            descArray.put(serializeDescriptorConfig(desc))
        }
        json.put("descriptors", descArray)
        return json
    }

    private fun serializeDescriptorConfig(config: GattDescriptorConfig): JSONObject {
        val json = JSONObject()
        json.put("uuid", config.uuid)
        json.put("permissions", config.permissions)
        json.put("initialValue", config.initialValue.toHexString())
        return json
    }

    private fun deserializeServiceConfig(json: JSONObject): GattServiceConfig {
        val charsArray = json.getJSONArray("characteristics")
        val chars = mutableListOf<GattCharacteristicConfig>()
        for (i in 0 until charsArray.length()) {
            chars.add(deserializeCharacteristicConfig(charsArray.getJSONObject(i)))
        }
        return GattServiceConfig(
            uuid = json.getString("uuid"),
            serviceType = json.getInt("serviceType"),
            characteristics = chars
        )
    }

    private fun deserializeCharacteristicConfig(json: JSONObject): GattCharacteristicConfig {
        val descArray = json.optJSONArray("descriptors") ?: JSONArray()
        val descs = mutableListOf<GattDescriptorConfig>()
        for (i in 0 until descArray.length()) {
            descs.add(deserializeDescriptorConfig(descArray.getJSONObject(i)))
        }
        return GattCharacteristicConfig(
            uuid = json.getString("uuid"),
            properties = json.getInt("properties"),
            permissions = json.getInt("permissions"),
            initialValue = json.optString("initialValue", "").hexToByteArray(),
            descriptors = descs
        )
    }

    private fun deserializeDescriptorConfig(json: JSONObject): GattDescriptorConfig {
        return GattDescriptorConfig(
            uuid = json.getString("uuid"),
            permissions = json.getInt("permissions"),
            initialValue = json.optString("initialValue", "").hexToByteArray()
        )
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }

    private fun String.hexToByteArray(): ByteArray {
        if (isEmpty()) return byteArrayOf()
        val len = length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(this[i], 16) shl 4) + Character.digit(this[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    private fun formatDate(timestamp: Long): String {
        val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
        return sdf.format(Date(timestamp))
    }
}
