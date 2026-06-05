/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import java.time.Instant

/**
 * Represents a discovered Bluetooth device.
 */
data class BluetoothDevice(
    val address: String,              // MAC address
    val name: String?,                 // Device name (nullable)
    val type: BluetoothType,              // BLE, Classic, Dual Mode
    val deviceClass: DeviceClass?,     // Bluetooth device class
    val bondState: BondState,          // Pairing state
    val rssi: Int?,                    // Signal strength (dBm)
    val txPower: Int?,                 // TX Power (dBm)
    val firstSeen: Instant,            // First discovery timestamp
    val lastSeen: Instant,             // Last seen timestamp
    val scanCount: Int = 1,            // Number of times discovered
    val services: List<String> = emptyList(),  // UUIDs of discovered services
    val manufacturerData: Map<Int, ByteArray> = emptyMap()  // Company ID -> data
) {
    /**
     * Check if this is a BLE device.
     */
    fun isBle(): Boolean = type == BluetoothType.BLE || type == BluetoothType.DUAL_MODE

    /**
     * Check if this is a Classic Bluetooth device.
     */
    fun isClassic(): Boolean = type == BluetoothType.CLASSIC || type == BluetoothType.DUAL_MODE

    /**
     * Check if device is bonded/paired.
     */
    fun isBonded(): Boolean = bondState == BondState.BONDED
}

/**
 * Bluetooth device type enumeration.
 */
enum class BluetoothType {
    BLE,           // Bluetooth Low Energy only
    CLASSIC,       // Classic Bluetooth only
    DUAL_MODE,     // Both BLE and Classic
    UNKNOWN        // Could not determine type
}

/**
 * Bluetooth device class categories.
 */
enum class DeviceClass {
    COMPUTER,
    PHONE,
    AUDIO_VIDEO,
    PERIPHERAL,
    WEARABLE,
    TOY,
    HEALTH,
    VEHICLE,
    IOT_DEVICE,
    UNCATEGORIZED,
    UNKNOWN
}

/**
 * Bond (pairing) state enumeration.
 */
enum class BondState {
    NONE,      // Not paired
    BONDING,   // Pairing in progress
    BONDED     // Successfully paired
}

/**
 * Connection state sealed class.
 */
sealed class ConnectionState {
    data object Disconnected : ConnectionState()

    data object Connecting : ConnectionState()

    data object Connected : ConnectionState()

    data object Disconnecting : ConnectionState()

    data class Error(val message: String) : ConnectionState()
}

/**
 * BLE Service information.
 */
data class BleService(
    val uuid: String,                  // Service UUID
    val primary: Boolean,              // Is primary service
    val characteristics: List<BleCharacteristic> = emptyList()
)

/**
 * BLE Characteristic information.
 */
data class BleCharacteristic(
    val uuid: String,                  // Characteristic UUID
    val properties: CharacteristicProperties,  // Read/write/notify properties
    val permissions: CharacteristicPermissions?,  // Permissions
    val value: ByteArray? = null,      // Current value (if readable)
    val descriptors: List<BleDescriptor> = emptyList()
) {
    /**
     * Check if characteristic is readable.
     */
    fun isReadable(): Boolean = properties.read

    /**
     * Check if characteristic is writable.
     */
    fun isWritable(): Boolean = properties.write || properties.writeWithoutResponse

    /**
     * Check if characteristic supports notifications.
     */
    fun canNotify(): Boolean = properties.notify || properties.indicate
}

/**
 * Characteristic properties.
 */
data class CharacteristicProperties(
    val read: Boolean = false,
    val write: Boolean = false,
    val writeWithoutResponse: Boolean = false,
    val notify: Boolean = false,
    val indicate: Boolean = false,
    val signedWrite: Boolean = false,
    val extendedProperties: Boolean = false
)

/**
 * Characteristic permissions.
 */
data class CharacteristicPermissions(
    val readAllowed: Boolean = true,
    val readEncrypted: Boolean = false,
    val readEncryptedMitm: Boolean = false,
    val writeAllowed: Boolean = true,
    val writeEncrypted: Boolean = false,
    val writeEncryptedMitm: Boolean = false,
    val writeSigned: Boolean = false,
    val writeSignedMitm: Boolean = false
)

/**
 * BLE Descriptor information.
 */
data class BleDescriptor(
    val uuid: String,
    val value: ByteArray? = null
)

/**
 * Vulnerability severity levels (CVSS-based).
 */
enum class VulnerabilitySeverity {
    CRITICAL,     // CVSS 9.0-10.0
    HIGH,         // CVSS 7.0-8.9
    MEDIUM,       // CVSS 4.0-6.9
    LOW,          // CVSS 0.1-3.9
    NONE,         // CVSS 0.0
    INFORMATIONAL  // Not scored, informational only
}

/**
 * Vulnerability information.
 */
data class Vulnerability(
    val id: String,                    // Unique identifier
    val cveId: String?,                // CVE identifier (e.g., CVE-2020-12345)
    val name: String,                  // Vulnerability name
    val description: String,           // Description
    val severity: VulnerabilitySeverity,  // Severity level
    val cvssScore: Double?,            // CVSS score (0.0-10.0)
    val affectedDevice: BluetoothDevice,  // Device with vulnerability
    val discoveredAt: Instant,         // When discovered
    val category: VulnerabilityCategory,  // Category of vulnerability
    val affectedBluetoothVersions: List<String>,  // Affected BT versions
    val references: List<String> = emptyList(),  // Reference URLs
    val mitigation: String?,           // Mitigation guidance
    val verified: Boolean = false,     // Manually verified
    val notes: String? = null          // Additional notes
)

/**
 * Vulnerability categories.
 */
enum class VulnerabilityCategory {
    PAIRING,           // Pairing/flaw vulnerabilities
    ENCRYPTION,        // Encryption weaknesses
    AUTHENTICATION,    // Authentication bypass
    AUTHORIZATION,     // Authorization issues
    PRIVILEGE_ESCALATION,  // Privilege escalation
    DENIAL_OF_SERVICE,     // DoS vulnerabilities
    INFORMATION_DISCLOSURE,  // Info leakage
    PROTOCOL,          // Protocol-level issues
    IMPLEMENTATION,    // Implementation bugs
    CONFIGURATION,     // Misconfiguration
    OTHER
}

/**
 * Known vulnerability definitions.
 */
data class VulnerabilityDefinition(
    val cveId: String,
    val name: String,
    val description: String,
    val severity: VulnerabilitySeverity,
    val cvssScore: Double,
    val category: VulnerabilityCategory,
    val affectedVersions: String,      // Bluetooth version ranges
    val affectedProfiles: List<String>,  // Affected profiles (GATT, SMP, etc.)
    val yearDiscovered: Int,
    val references: List<String>,
    val mitigation: String,
    val testMethodology: String        // How to test for this vulnerability
)

/**
 * Fuzzing configuration.
 */
data class FuzzConfig(
    val targetDevice: BluetoothDevice,
    val targetService: BleService?,    // Service to fuzz (null = all)
    val targetCharacteristic: BleCharacteristic?,  // Characteristic to fuzz
    val fuzzMethod: FuzzMethod,        // Fuzzing strategy
    val packetCount: Int,              // Number of packets to send
    val packetsPerSecond: Int,         // Rate limiting
    val randomSeed: Long?,             // Seed for reproducibility
    val dataPatterns: List<FuzzDataPattern>,  // Data patterns to use
    val durationSeconds: Int?,         // Max duration (null = count-based)
    val stopOnError: Boolean = true,   // Stop on device error
    val stopOnDisconnect: Boolean = true,  // Stop on disconnect
    val capturePackets: Boolean = true,  // Capture packets
    val captureNotifications: Boolean = true  // Capture notifications
)

/**
 * Fuzzing methods.
 */
enum class FuzzMethod {
    BIT_FLIP,              // Flip individual bits
    BYTE_FLIP,             // Flip entire bytes
    RANDOM,                // Random bytes
    SEQUENTIAL,            // Sequential patterns
    LENGTH_FUZZING,        // Vary length (buffer overflow)
    BOUNDARY_CASE,         // Boundary values
    FORMAT_STRING,         // Format string patterns
    INJECTION,             // Injection patterns
    MUTATION,              // Mutate valid packets
    PROTOCOL_STATE,        // State machine abuse
    REPLAY,                // Replay captured packets
    DELAY                  // Timing-based fuzzing
}

/**
 * Fuzzing data patterns.
 */
data class FuzzDataPattern(
    val name: String,
    val description: String,
    val patternType: PatternType,
    val data: ByteArray,
    val length: Int = data.size
)

/**
 * Pattern types for fuzzing.
 */
enum class PatternType {
    MALFORMED,         // Malformed data
    OVERLONG,          // Excessively long data
    UNDERSIZED,        // Too short data
    NULL_BYTES,        // Contains null bytes
    SPECIAL_CHARS,     // Special characters
    EDGE_CASE,         // Boundary values
    RANDOM,            // Random data
    VALID_MUTATED,     // Valid data with mutations
    KNOWN_EXPLOIT      // Known exploit patterns
}

/**
 * Fuzzing test result.
 */
data class FuzzResult(
    val id: String,
    val config: FuzzConfig,
    val startTime: Instant,
    val endTime: Instant?,
    val status: FuzzStatus,
    val packetsSent: Int,
    val packetsReceived: Int,
    val errors: List<FuzzError>,
    val findings: List<FuzzFinding>,
    val captureFile: String?,          // Path to packet capture
    val reportGenerated: Boolean = false
) {
    /**
     * Get duration of fuzzing test.
     */
    fun getDuration(): java.time.Duration? {
        return if (endTime != null) {
            java.time.Duration.between(startTime, endTime)
        } else null
    }

    /**
     * Get success rate (received/sent * 100).
     */
    fun getSuccessRate(): Double {
        return if (packetsSent > 0) {
            (packetsReceived.toDouble() / packetsSent.toDouble()) * 100.0
        } else 0.0
    }
}

/**
 * Fuzzing status.
 */
enum class FuzzStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    STOPPED,
    ERROR
}

/**
 * Fuzzing error record.
 */
data class FuzzError(
    val timestamp: Instant,
    val packetNumber: Int,
    val errorCode: Int?,              // Android/error code
    val errorMessage: String,
    val severity: ErrorSeverity,
    val packetData: ByteArray? = null  // Problematic packet
)

/**
 * Error severity levels.
 */
enum class ErrorSeverity {
    CRITICAL,     // Device crashed/rebooted
    HIGH,         // Device disconnected/error state
    MEDIUM,       // Operation failed
    LOW,          // Non-fatal error
    INFO          // Informational
}

/**
 * Fuzzing finding (potential vulnerability).
 */
data class FuzzFinding(
    val timestamp: Instant,
    val packetNumber: Int,
    val description: String,
    val severity: VulnerabilitySeverity,
    val packetData: ByteArray?,
    val response: ByteArray?,
    val category: FindingCategory,
    val reproducible: Boolean = false,
    val additionalNotes: String? = null
)

/**
 * Finding categories from fuzzing.
 */
enum class FindingCategory {
    CRASH,              // Device/service crash
    HANG,               // Device/service hang
    MEMORY_CORRUPTION,  // Memory corruption detected
    UNEXPECTED_RESPONSE,  // Unexpected response
    NO_RESPONSE,        // No response (DoS)
    DELAYED_RESPONSE,   // Abnormally delayed response
    STATE_ERROR,        // State machine error
    BUFFER_OVERFLOW,    // Potential buffer overflow
    INFORMATION_LEAK,   // Information disclosure
    BYPASS              // Security bypass
}

/**
 * Key extraction target types.
 */
enum class KeyType {
    IRK,           // Identity Resolving Key
    LTK,           // Long Term Key
    CSRK,          // Connection Signature Resolving Key
    LINK_KEY,      // Classic Bluetooth Link Key
    PRIVATE_KEY    // Device private key (rare)
}

/**
 * Key extraction result.
 */
data class KeyExtractionResult(
    val id: String,
    val targetDevice: BluetoothDevice,
    val keyType: KeyType,
    val extracted: Boolean,
    val keyValue: ByteArray?,          // Extracted key (encrypted storage)
    val method: ExtractionMethod,
    val confidence: ExtractionConfidence,
    val timestamp: Instant,
    val notes: String? = null
) {
    /**
     * Check if key extraction was successful.
     */
    fun isSuccess(): Boolean = extracted && keyValue != null
}

/**
 * Key extraction methods.
 */
enum class ExtractionMethod {
    PASSIVE_MONITORING,     // Monitor pairing traffic
    ACTIVE_PROMPT,          // Prompt device during pairing
    KNOWN_PLAINTEXT,        // Known plaintext attack
    BRUTE_FORCE,            // Brute force (very slow)
    DATABASE_LOOKUP,        // Lookup in known databases
    MEMORY_DUMP,            // Dump from device memory
    LOG_ANALYSIS,           // Analyze device logs
    CONFIGURATION,          // Extract from config
    OTHER
}

/**
 * Extraction confidence levels.
 */
enum class ExtractionConfidence {
    CERTAIN,         // Definitely correct
    HIGH,            // Very likely correct
    MEDIUM,          // Possibly correct
    LOW,             // Unlikely to be correct
    UNKNOWN          // Cannot determine
}

/**
 * Packet capture data.
 */
data class PacketCapture(
    val id: String,
    val deviceAddress: String,
    val startTime: Instant,
    val endTime: Instant?,
    val packetCount: Int,
    val fileType: CaptureFileType,
    val filePath: String,
    val fileSizeBytes: Long,
    val protocols: List<String>,  // Protocols seen
    val notes: String? = null
)

/**
 * Packet capture file types.
 */
enum class CaptureFileType {
    PCAP,          // Wireshark PCAP
    PCAPNG,        // Wireshark PCAPNG
    JSON,          // JSON format
    CSV,           // CSV format
    CUSTOM         // Custom format
}

/**
 * Security assessment report.
 */
data class SecurityReport(
    val id: String,
    val authId: String,
    val title: String,
    val generatedAt: Instant,
    val testPeriod: ReportPeriod,
    val targetDevices: List<BluetoothDevice>,
    val vulnerabilities: List<Vulnerability>,
    val fuzzingResults: List<FuzzResult>,
    val keyExtractionResults: List<KeyExtractionResult>,
    val executiveSummary: String,
    val findings: List<ReportFinding>,
    val recommendations: List<Recommendation>,
    val appendix: ReportAppendix,
    val status: ReportStatus
)

/**
 * Report time period.
 */
data class ReportPeriod(
    val start: Instant,
    val end: Instant
)

/**
 * Report finding summary.
 */
data class ReportFinding(
    val category: FindingCategory,
    val severity: VulnerabilitySeverity,
    val count: Int,
    val description: String,
    val affectedDevices: List<String>  // Device addresses
)

/**
 * Security recommendations.
 */
data class Recommendation(
    val priority: RecommendationPriority,
    val title: String,
    val description: String,
    val affectedDevices: List<String>,
    val implementation: String,
    val verification: String
)

/**
 * Recommendation priority levels.
 */
enum class RecommendationPriority {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW
}

/**
 * Report appendix information.
 */
data class ReportAppendix(
    val toolsUsed: List<String>,
    val testMethodology: String,
    val limitations: List<String>,
    val glossary: Map<String, String>,
    val references: List<String>
)

/**
 * Report status.
 */
enum class ReportStatus {
    DRAFT,
    REVIEW,
    FINAL,
    ARCHIVED
}


