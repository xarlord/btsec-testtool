/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant

/**
 * Unit tests for Bluetooth domain model data classes defined in BluetoothModels.kt.
 *
 * Covers construction, default values, copy(), equals/hashCode, toString(),
 * and domain helper methods for every data class and sealed class in the file.
 */
@DisplayName("Bluetooth Models")
class BluetoothModelsTest {

    // ── Shared fixtures ──

    private val fixedInstant: Instant = Instant.parse("2026-01-15T12:00:00Z")

    private fun testDevice(
        address: String = "AA:BB:CC:DD:EE:FF",
        name: String? = "Test Device",
        type: BluetoothType = BluetoothType.BLE,
        bondState: BondState = BondState.NONE
    ) = BluetoothDevice(
        address = address,
        name = name,
        type = type,
        deviceClass = DeviceClass.UNCATEGORIZED,
        bondState = bondState,
        rssi = -60,
        txPower = null,
        firstSeen = fixedInstant,
        lastSeen = fixedInstant
    )

    // ── BluetoothDevice ──

    @Nested
    @DisplayName("BluetoothDevice")
    inner class BluetoothDeviceTest {

        @Test
        @DisplayName("constructs with required parameters and default values")
        fun construction() {
            val device = BluetoothDevice(
                address = "11:22:33:44:55:66",
                name = null,
                type = BluetoothType.CLASSIC,
                deviceClass = null,
                bondState = BondState.BONDED,
                rssi = null,
                txPower = null,
                firstSeen = fixedInstant,
                lastSeen = fixedInstant
            )

            assertThat(device.address).isEqualTo("11:22:33:44:55:66")
            assertThat(device.name).isNull()
            assertThat(device.type).isEqualTo(BluetoothType.CLASSIC)
            assertThat(device.deviceClass).isNull()
            assertThat(device.bondState).isEqualTo(BondState.BONDED)
            assertThat(device.rssi).isNull()
            assertThat(device.txPower).isNull()
            // Defaults
            assertThat(device.scanCount).isEqualTo(1)
            assertThat(device.services).isEmpty()
            assertThat(device.manufacturerData).isEmpty()
        }

        @Test
        @DisplayName("copy() changes selected fields")
        fun copyWorks() {
            val original = testDevice()
            val copied = original.copy(name = "Renamed", rssi = -42)

            assertThat(copied.name).isEqualTo("Renamed")
            assertThat(copied.rssi).isEqualTo(-42)
            assertThat(copied.address).isEqualTo(original.address)
        }

        @Test
        @DisplayName("equals and hashCode contract")
        fun equalsHashCode() {
            val a = testDevice()
            val b = testDevice()
            assertThat(a).isEqualTo(b)
            assertThat(a.hashCode()).isEqualTo(b.hashCode())

            val c = testDevice(address = "11:22:33:44:55:66")
            assertThat(a).isNotEqualTo(c)
        }

        @Test
        @DisplayName("toString() contains field names")
        fun toStringContainsFields() {
            val device = testDevice()
            val s = device.toString()
            assertThat(s).contains("address=")
            assertThat(s).contains("name=")
            assertThat(s).contains("type=")
        }

        @Test
        @DisplayName("isBle() returns true for BLE and DUAL_MODE")
        fun isBle() {
            assertThat(testDevice(type = BluetoothType.BLE).isBle()).isTrue()
            assertThat(testDevice(type = BluetoothType.DUAL_MODE).isBle()).isTrue()
            assertThat(testDevice(type = BluetoothType.CLASSIC).isBle()).isFalse()
            assertThat(testDevice(type = BluetoothType.UNKNOWN).isBle()).isFalse()
        }

        @Test
        @DisplayName("isClassic() returns true for CLASSIC and DUAL_MODE")
        fun isClassic() {
            assertThat(testDevice(type = BluetoothType.CLASSIC).isClassic()).isTrue()
            assertThat(testDevice(type = BluetoothType.DUAL_MODE).isClassic()).isTrue()
            assertThat(testDevice(type = BluetoothType.BLE).isClassic()).isFalse()
        }

        @Test
        @DisplayName("isBonded() returns true only for BONDED")
        fun isBonded() {
            assertThat(testDevice(bondState = BondState.BONDED).isBonded()).isTrue()
            assertThat(testDevice(bondState = BondState.NONE).isBonded()).isFalse()
            assertThat(testDevice(bondState = BondState.BONDING).isBonded()).isFalse()
        }
    }

    // ── Enums (construction & completeness) ──

    @Nested
    @DisplayName("BluetoothType enum")
    inner class BluetoothTypeTest {

        @Test
        @DisplayName("has expected values")
        fun values() {
            assertThat(BluetoothType.values()).asList().containsExactly(
                BluetoothType.BLE,
                BluetoothType.CLASSIC,
                BluetoothType.DUAL_MODE,
                BluetoothType.UNKNOWN
            )
        }
    }

    @Nested
    @DisplayName("DeviceClass enum")
    inner class DeviceClassTest {

        @Test
        @DisplayName("has expected values")
        fun values() {
            assertThat(DeviceClass.values()).hasLength(11)
        }
    }

    @Nested
    @DisplayName("BondState enum")
    inner class BondStateTest {

        @Test
        @DisplayName("has NONE, BONDING, BONDED")
        fun values() {
            assertThat(BondState.values()).asList().containsExactly(
                BondState.NONE, BondState.BONDING, BondState.BONDED
            ).inOrder()
        }
    }

    // ── ConnectionState sealed class ──

    @Nested
    @DisplayName("ConnectionState sealed class")
    inner class ConnectionStateTest {

        @Test
        @DisplayName("Disconnected is a singleton data object")
        fun disconnected() {
            assertThat(ConnectionState.Disconnected).isEqualTo(ConnectionState.Disconnected)
        }

        @Test
        @DisplayName("Connected is a singleton data object")
        fun connected() {
            assertThat(ConnectionState.Connected).isEqualTo(ConnectionState.Connected)
        }

        @Test
        @DisplayName("Connecting is a singleton data object")
        fun connecting() {
            assertThat(ConnectionState.Connecting).isEqualTo(ConnectionState.Connecting)
        }

        @Test
        @DisplayName("Disconnecting is a singleton data object")
        fun disconnecting() {
            assertThat(ConnectionState.Disconnecting).isEqualTo(ConnectionState.Disconnecting)
        }

        @Test
        @DisplayName("Error holds a message")
        fun errorHoldsMessage() {
            val error = ConnectionState.Error("timeout")
            assertThat(error.message).isEqualTo("timeout")
        }

        @Test
        @DisplayName("when-expression is exhaustive")
        fun whenExhaustive() {
            fun classify(state: ConnectionState): String = when (state) {
                is ConnectionState.Disconnected -> "disconnected"
                is ConnectionState.Connecting -> "connecting"
                is ConnectionState.Connected -> "connected"
                is ConnectionState.Disconnecting -> "disconnecting"
                is ConnectionState.Error -> "error"
            }
            assertThat(classify(ConnectionState.Connected)).isEqualTo("connected")
            assertThat(classify(ConnectionState.Error("x"))).isEqualTo("error")
        }
    }

    // ── BleService ──

    @Nested
    @DisplayName("BleService")
    inner class BleServiceTest {

        @Test
        @DisplayName("constructs with defaults")
        fun construction() {
            val service = BleService(uuid = "0000180f-0000-1000-8000-00805f9b34fb", primary = true)
            assertThat(service.uuid).isEqualTo("0000180f-0000-1000-8000-00805f9b34fb")
            assertThat(service.primary).isTrue()
            assertThat(service.characteristics).isEmpty()
        }

        @Test
        @DisplayName("equals/hashCode/toString")
        fun equalsEtc() {
            val a = BleService("uuid1", true, emptyList())
            val b = BleService("uuid1", true, emptyList())
            assertThat(a).isEqualTo(b)
            assertThat(a.hashCode()).isEqualTo(b.hashCode())
            assertThat(a.toString()).contains("uuid=")
        }

        @Test
        @DisplayName("copy() changes fields")
        fun copy() {
            val original = BleService("uuid1", true)
            val copied = original.copy(primary = false)
            assertThat(copied.primary).isFalse()
        }
    }

    // ── BleCharacteristic ──

    @Nested
    @DisplayName("BleCharacteristic")
    inner class BleCharacteristicTest {

        private val readNotifyProps = CharacteristicProperties(read = true, notify = true)
        private val writeProps = CharacteristicProperties(write = true, writeWithoutResponse = true)

        @Test
        @DisplayName("constructs with defaults")
        fun construction() {
            val char = BleCharacteristic(
                uuid = "char-uuid",
                properties = readNotifyProps,
                permissions = null
            )
            assertThat(char.value).isNull()
            assertThat(char.descriptors).isEmpty()
        }

        @Test
        @DisplayName("isReadable / isWritable / canNotify")
        fun helperMethods() {
            val readable = BleCharacteristic("u1", readNotifyProps, null)
            assertThat(readable.isReadable()).isTrue()
            assertThat(readable.isWritable()).isFalse()
            assertThat(readable.canNotify()).isTrue()

            val writable = BleCharacteristic("u2", writeProps, null)
            assertThat(writable.isReadable()).isFalse()
            assertThat(writable.isWritable()).isTrue()
            assertThat(writable.canNotify()).isFalse()
        }

        @Test
        @DisplayName("copy() and toString()")
        fun copyAndToString() {
            val char = BleCharacteristic("uuid", readNotifyProps, null)
            val copied = char.copy(uuid = "new-uuid")
            assertThat(copied.uuid).isEqualTo("new-uuid")
            assertThat(char.toString()).contains("uuid=")
        }
    }

    // ── CharacteristicProperties ──

    @Nested
    @DisplayName("CharacteristicProperties")
    inner class CharacteristicPropertiesTest {

        @Test
        @DisplayName("all defaults are false")
        fun defaults() {
            val props = CharacteristicProperties()
            assertThat(props.read).isFalse()
            assertThat(props.write).isFalse()
            assertThat(props.writeWithoutResponse).isFalse()
            assertThat(props.notify).isFalse()
            assertThat(props.indicate).isFalse()
            assertThat(props.signedWrite).isFalse()
            assertThat(props.extendedProperties).isFalse()
        }

        @Test
        @DisplayName("equals and hashCode")
        fun equalsHashCode() {
            val a = CharacteristicProperties(read = true, notify = true)
            val b = CharacteristicProperties(read = true, notify = true)
            assertThat(a).isEqualTo(b)
            assertThat(a.hashCode()).isEqualTo(b.hashCode())
        }
    }

    // ── CharacteristicPermissions ──

    @Nested
    @DisplayName("CharacteristicPermissions")
    inner class CharacteristicPermissionsTest {

        @Test
        @DisplayName("defaults: readAllowed and writeAllowed true, rest false")
        fun defaults() {
            val perms = CharacteristicPermissions()
            assertThat(perms.readAllowed).isTrue()
            assertThat(perms.writeAllowed).isTrue()
            assertThat(perms.readEncrypted).isFalse()
            assertThat(perms.readEncryptedMitm).isFalse()
            assertThat(perms.writeEncrypted).isFalse()
            assertThat(perms.writeEncryptedMitm).isFalse()
            assertThat(perms.writeSigned).isFalse()
            assertThat(perms.writeSignedMitm).isFalse()
        }

        @Test
        @DisplayName("equals and hashCode")
        fun equalsHashCode() {
            val a = CharacteristicPermissions(readEncrypted = true)
            val b = CharacteristicPermissions(readEncrypted = true)
            assertThat(a).isEqualTo(b)
        }
    }

    // ── BleDescriptor ──

    @Nested
    @DisplayName("BleDescriptor")
    inner class BleDescriptorTest {

        @Test
        @DisplayName("constructs with defaults")
        fun construction() {
            val desc = BleDescriptor(uuid = "desc-uuid")
            assertThat(desc.value).isNull()
        }

        @Test
        @DisplayName("equals and toString")
        fun equalsEtc() {
            val a = BleDescriptor("uuid1")
            val b = BleDescriptor("uuid1")
            assertThat(a).isEqualTo(b)
            assertThat(a.toString()).contains("uuid=")
        }
    }

    // ── VulnerabilitySeverity & VulnerabilityCategory enums ──

    @Nested
    @DisplayName("VulnerabilitySeverity enum")
    inner class VulnerabilitySeverityTest {

        @Test
        @DisplayName("has expected values")
        fun values() {
            assertThat(VulnerabilitySeverity.values()).asList().containsExactly(
                VulnerabilitySeverity.CRITICAL,
                VulnerabilitySeverity.HIGH,
                VulnerabilitySeverity.MEDIUM,
                VulnerabilitySeverity.LOW,
                VulnerabilitySeverity.NONE,
                VulnerabilitySeverity.INFORMATIONAL
            ).inOrder()
        }
    }

    @Nested
    @DisplayName("VulnerabilityCategory enum")
    inner class VulnerabilityCategoryTest {

        @Test
        @DisplayName("has expected count")
        fun values() {
            assertThat(VulnerabilityCategory.values()).hasLength(11)
        }
    }

    // ── Vulnerability ──

    @Nested
    @DisplayName("Vulnerability")
    inner class VulnerabilityTest {

        @Test
        @DisplayName("constructs with required and default values")
        fun construction() {
            val vuln = Vulnerability(
                id = "v-1",
                cveId = "CVE-2026-0001",
                name = "TestVuln",
                description = "desc",
                severity = VulnerabilitySeverity.HIGH,
                cvssScore = 7.5,
                affectedDevice = testDevice(),
                discoveredAt = fixedInstant,
                category = VulnerabilityCategory.ENCRYPTION,
                affectedBluetoothVersions = listOf("5.0"),
                mitigation = null
            )
            assertThat(vuln.references).isEmpty()
            assertThat(vuln.mitigation).isNull()
            assertThat(vuln.verified).isFalse()
            assertThat(vuln.notes).isNull()
        }

        @Test
        @DisplayName("copy(), equals, toString()")
        fun copyEqualsToString() {
            val vuln = Vulnerability(
                id = "v-1",
                cveId = null,
                name = "V",
                description = "D",
                severity = VulnerabilitySeverity.LOW,
                cvssScore = null,
                affectedDevice = testDevice(),
                discoveredAt = fixedInstant,
                category = VulnerabilityCategory.OTHER,
                affectedBluetoothVersions = emptyList(),
                mitigation = null
            )
            val copied = vuln.copy(verified = true)
            assertThat(copied.verified).isTrue()
            assertThat(vuln).isNotEqualTo(copied)
            assertThat(vuln.toString()).contains("id=")
        }
    }

    // ── VulnerabilityDefinition ──

    @Nested
    @DisplayName("VulnerabilityDefinition")
    inner class VulnerabilityDefinitionTest {

        @Test
        @DisplayName("construction and equals")
        fun construction() {
            val def = VulnerabilityDefinition(
                cveId = "CVE-2026-0001",
                name = "Test",
                description = "desc",
                severity = VulnerabilitySeverity.CRITICAL,
                cvssScore = 9.8,
                category = VulnerabilityCategory.PAIRING,
                affectedVersions = "All",
                affectedProfiles = listOf("SMP"),
                yearDiscovered = 2026,
                references = listOf("https://example.com"),
                mitigation = "Patch",
                testMethodology = "Fuzz"
            )
            assertThat(def.cveId).isEqualTo("CVE-2026-0001")
            assertThat(def.yearDiscovered).isEqualTo(2026)

            val dup = def.copy()
            assertThat(def).isEqualTo(dup)
            assertThat(def.toString()).contains("cveId=")
        }
    }

    // ── FuzzConfig ──

    @Nested
    @DisplayName("FuzzConfig")
    inner class FuzzConfigTest {

        @Test
        @DisplayName("default values for stopOnError, stopOnDisconnect, capturePackets, captureNotifications")
        fun defaults() {
            val config = FuzzConfig(
                targetDevice = testDevice(),
                targetService = null,
                targetCharacteristic = null,
                fuzzMethod = FuzzMethod.RANDOM,
                packetCount = 100,
                packetsPerSecond = 10,
                randomSeed = null,
                dataPatterns = emptyList(),
                durationSeconds = null
            )
            assertThat(config.stopOnError).isTrue()
            assertThat(config.stopOnDisconnect).isTrue()
            assertThat(config.capturePackets).isTrue()
            assertThat(config.captureNotifications).isTrue()
        }

        @Test
        @DisplayName("copy and equals")
        fun copyEquals() {
            val config = FuzzConfig(
                targetDevice = testDevice(),
                targetService = null,
                targetCharacteristic = null,
                fuzzMethod = FuzzMethod.BIT_FLIP,
                packetCount = 50,
                packetsPerSecond = 5,
                randomSeed = 42L,
                dataPatterns = emptyList(),
                durationSeconds = 30
            )
            val copied = config.copy(packetCount = 200)
            assertThat(copied.packetCount).isEqualTo(200)
            assertThat(config).isNotEqualTo(copied)
        }
    }

    // ── FuzzMethod, FuzzStatus, PatternType, ErrorSeverity, FindingCategory enums ──

    @Nested
    @DisplayName("FuzzMethod enum")
    inner class FuzzMethodTest {

        @Test
        @DisplayName("has expected count")
        fun count() {
            assertThat(FuzzMethod.values()).hasLength(12)
        }
    }

    @Nested
    @DisplayName("FuzzStatus enum")
    inner class FuzzStatusTest {

        @Test
        @DisplayName("has expected values")
        fun values() {
            assertThat(FuzzStatus.values()).asList().containsExactly(
                FuzzStatus.PENDING, FuzzStatus.RUNNING,
                FuzzStatus.COMPLETED, FuzzStatus.STOPPED, FuzzStatus.ERROR
            ).inOrder()
        }
    }

    @Nested
    @DisplayName("PatternType enum")
    inner class PatternTypeTest {

        @Test
        @DisplayName("has expected count")
        fun count() {
            assertThat(PatternType.values()).hasLength(9)
        }
    }

    @Nested
    @DisplayName("ErrorSeverity enum")
    inner class ErrorSeverityTest {

        @Test
        @DisplayName("has expected count")
        fun count() {
            assertThat(ErrorSeverity.values()).hasLength(5)
        }
    }

    @Nested
    @DisplayName("FindingCategory enum")
    inner class FindingCategoryTest {

        @Test
        @DisplayName("has expected count")
        fun count() {
            assertThat(FindingCategory.values()).hasLength(10)
        }
    }

    // ── FuzzDataPattern ──

    @Nested
    @DisplayName("FuzzDataPattern")
    inner class FuzzDataPatternTest {

        @Test
        @DisplayName("length defaults to data.size")
        fun lengthDefault() {
            val pattern = FuzzDataPattern(
                name = "test",
                description = "desc",
                patternType = PatternType.RANDOM,
                data = byteArrayOf(0x01, 0x02, 0x03)
            )
            assertThat(pattern.length).isEqualTo(3)
        }

        @Test
        @DisplayName("copy overrides length")
        fun copyOverridesLength() {
            val pattern = FuzzDataPattern(
                name = "test", description = "desc",
                patternType = PatternType.MALFORMED,
                data = byteArrayOf(0x00)
            )
            val copied = pattern.copy(length = 99)
            assertThat(copied.length).isEqualTo(99)
        }
    }

    // ── FuzzError ──

    @Nested
    @DisplayName("FuzzError")
    inner class FuzzErrorTest {

        @Test
        @DisplayName("construction with defaults")
        fun construction() {
            val err = FuzzError(
                timestamp = fixedInstant,
                packetNumber = 5,
                errorCode = 42,
                errorMessage = "crash",
                severity = ErrorSeverity.CRITICAL
            )
            assertThat(err.packetData).isNull()
        }

        @Test
        @DisplayName("toString contains field names")
        fun toStringFields() {
            val err = FuzzError(fixedInstant, 1, null, "msg", ErrorSeverity.LOW)
            assertThat(err.toString()).contains("packetNumber=")
        }
    }

    // ── FuzzResult ──

    @Nested
    @DisplayName("FuzzResult")
    inner class FuzzResultTest {

        private fun makeResult(
            endTime: Instant? = fixedInstant.plusSeconds(60),
            packetsSent: Int = 100,
            packetsReceived: Int = 80
        ) = FuzzResult(
            id = "fuzz-1",
            config = FuzzConfig(
                targetDevice = testDevice(),
                targetService = null,
                targetCharacteristic = null,
                fuzzMethod = FuzzMethod.RANDOM,
                packetCount = 100,
                packetsPerSecond = 10,
                randomSeed = null,
                dataPatterns = emptyList(),
                durationSeconds = null
            ),
            startTime = fixedInstant,
            endTime = endTime,
            status = FuzzStatus.COMPLETED,
            packetsSent = packetsSent,
            packetsReceived = packetsReceived,
            errors = emptyList(),
            findings = emptyList(),
            captureFile = null
        )

        @Test
        @DisplayName("getDuration() returns duration when endTime is set")
        fun getDuration() {
            val result = makeResult()
            val duration = result.getDuration()
            assertThat(duration).isNotNull()
            assertThat(duration!!.seconds).isEqualTo(60)
        }

        @Test
        @DisplayName("getDuration() returns null when endTime is null")
        fun getDurationNull() {
            val result = makeResult(endTime = null)
            assertThat(result.getDuration()).isNull()
        }

        @Test
        @DisplayName("getSuccessRate() computes correctly")
        fun successRate() {
            val result = makeResult(packetsSent = 200, packetsReceived = 150)
            assertThat(result.getSuccessRate()).isWithin(0.01).of(75.0)
        }

        @Test
        @DisplayName("getSuccessRate() returns 0 when packetsSent is 0")
        fun successRateZeroSent() {
            val result = makeResult(packetsSent = 0, packetsReceived = 0)
            assertThat(result.getSuccessRate()).isEqualTo(0.0)
        }

        @Test
        @DisplayName("reportGenerated defaults to false")
        fun defaultReportGenerated() {
            val result = makeResult()
            assertThat(result.reportGenerated).isFalse()
        }

        @Test
        @DisplayName("copy, equals, toString")
        fun copyEtc() {
            val result = makeResult()
            val copied = result.copy(reportGenerated = true)
            assertThat(copied.reportGenerated).isTrue()
            assertThat(result).isNotEqualTo(copied)
            assertThat(result.toString()).contains("id=")
        }
    }

    // ── FuzzFinding ──

    @Nested
    @DisplayName("FuzzFinding")
    inner class FuzzFindingTest {

        @Test
        @DisplayName("construction with defaults")
        fun construction() {
            val finding = FuzzFinding(
                timestamp = fixedInstant,
                packetNumber = 10,
                description = "crash",
                severity = VulnerabilitySeverity.HIGH,
                packetData = byteArrayOf(0x01),
                response = null,
                category = FindingCategory.CRASH
            )
            assertThat(finding.reproducible).isFalse()
            assertThat(finding.additionalNotes).isNull()
        }

        @Test
        @DisplayName("toString contains field names")
        fun toStringFields() {
            val finding = FuzzFinding(
                fixedInstant, 1, "desc", VulnerabilitySeverity.LOW,
                null, null, FindingCategory.HANG
            )
            assertThat(finding.toString()).contains("description=")
        }
    }

    // ── KeyType, ExtractionMethod, ExtractionConfidence enums ──

    @Nested
    @DisplayName("KeyType enum")
    inner class KeyTypeTest {

        @Test
        @DisplayName("has expected values")
        fun values() {
            assertThat(KeyType.values()).asList().containsExactly(
                KeyType.IRK, KeyType.LTK, KeyType.CSRK,
                KeyType.LINK_KEY, KeyType.PRIVATE_KEY
            ).inOrder()
        }
    }

    @Nested
    @DisplayName("ExtractionMethod enum")
    inner class ExtractionMethodTest {

        @Test
        @DisplayName("has expected count")
        fun count() {
            assertThat(ExtractionMethod.values()).hasLength(9)
        }
    }

    @Nested
    @DisplayName("ExtractionConfidence enum")
    inner class ExtractionConfidenceTest {

        @Test
        @DisplayName("has expected values")
        fun values() {
            assertThat(ExtractionConfidence.values()).asList().containsExactly(
                ExtractionConfidence.CERTAIN, ExtractionConfidence.HIGH,
                ExtractionConfidence.MEDIUM, ExtractionConfidence.LOW,
                ExtractionConfidence.UNKNOWN
            ).inOrder()
        }
    }

    // ── KeyExtractionResult ──

    @Nested
    @DisplayName("KeyExtractionResult")
    inner class KeyExtractionResultTest {

        @Test
        @DisplayName("isSuccess() true when extracted and keyValue non-null")
        fun isSuccessTrue() {
            val result = KeyExtractionResult(
                id = "k-1",
                targetDevice = testDevice(),
                keyType = KeyType.LTK,
                extracted = true,
                keyValue = byteArrayOf(0x01),
                method = ExtractionMethod.DATABASE_LOOKUP,
                confidence = ExtractionConfidence.CERTAIN,
                timestamp = fixedInstant
            )
            assertThat(result.isSuccess()).isTrue()
        }

        @Test
        @DisplayName("isSuccess() false when extracted but keyValue is null")
        fun isSuccessFalseNullKey() {
            val result = KeyExtractionResult(
                id = "k-2",
                targetDevice = testDevice(),
                keyType = KeyType.IRK,
                extracted = true,
                keyValue = null,
                method = ExtractionMethod.LOG_ANALYSIS,
                confidence = ExtractionConfidence.LOW,
                timestamp = fixedInstant
            )
            assertThat(result.isSuccess()).isFalse()
        }

        @Test
        @DisplayName("isSuccess() false when extracted is false")
        fun isSuccessFalseNotExtracted() {
            val result = KeyExtractionResult(
                id = "k-3",
                targetDevice = testDevice(),
                keyType = KeyType.LTK,
                extracted = false,
                keyValue = null,
                method = ExtractionMethod.BRUTE_FORCE,
                confidence = ExtractionConfidence.UNKNOWN,
                timestamp = fixedInstant
            )
            assertThat(result.isSuccess()).isFalse()
        }

        @Test
        @DisplayName("notes defaults to null")
        fun notesDefault() {
            val result = KeyExtractionResult(
                id = "k-4", targetDevice = testDevice(), keyType = KeyType.CSRK,
                extracted = false, keyValue = null,
                method = ExtractionMethod.CONFIGURATION,
                confidence = ExtractionConfidence.MEDIUM,
                timestamp = fixedInstant
            )
            assertThat(result.notes).isNull()
        }

        @Test
        @DisplayName("copy and equals")
        fun copyEquals() {
            val result = KeyExtractionResult(
                id = "k-5", targetDevice = testDevice(), keyType = KeyType.LINK_KEY,
                extracted = false, keyValue = null,
                method = ExtractionMethod.MEMORY_DUMP,
                confidence = ExtractionConfidence.HIGH,
                timestamp = fixedInstant
            )
            val copied = result.copy(extracted = true, keyValue = byteArrayOf(0xFF.toByte()))
            assertThat(copied.isSuccess()).isTrue()
            assertThat(result).isNotEqualTo(copied)
        }
    }

    // ── PacketCapture ──

    @Nested
    @DisplayName("PacketCapture")
    inner class PacketCaptureTest {

        @Test
        @DisplayName("construction and defaults")
        fun construction() {
            val capture = PacketCapture(
                id = "cap-1",
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                startTime = fixedInstant,
                endTime = fixedInstant.plusSeconds(60),
                packetCount = 500,
                fileType = CaptureFileType.PCAP,
                filePath = "/tmp/capture.pcap",
                fileSizeBytes = 1024L,
                protocols = listOf("L2CAP", "ATT")
            )
            assertThat(capture.notes).isNull()
            assertThat(capture.packetCount).isEqualTo(500)
        }

        @Test
        @DisplayName("equals and toString")
        fun equalsEtc() {
            val a = PacketCapture("c1", "AA", fixedInstant, null, 0,
                CaptureFileType.PCAP, "/tmp/a.pcap", 0, emptyList())
            val b = PacketCapture("c1", "AA", fixedInstant, null, 0,
                CaptureFileType.PCAP, "/tmp/a.pcap", 0, emptyList())
            assertThat(a).isEqualTo(b)
            assertThat(a.toString()).contains("id=")
        }
    }

    // ── CaptureFileType enum ──

    @Nested
    @DisplayName("CaptureFileType enum")
    inner class CaptureFileTypeTest {

        @Test
        @DisplayName("has expected values")
        fun values() {
            assertThat(CaptureFileType.values()).asList().containsExactly(
                CaptureFileType.PCAP, CaptureFileType.PCAPNG,
                CaptureFileType.JSON, CaptureFileType.CSV, CaptureFileType.CUSTOM
            ).inOrder()
        }
    }

    // ── SecurityReport & related ──

    @Nested
    @DisplayName("SecurityReport")
    inner class SecurityReportTest {

        @Test
        @DisplayName("construction with all fields")
        fun construction() {
            val report = SecurityReport(
                id = "rpt-1",
                authId = "BTSEC-20260207-TEST",
                title = "Test Report",
                generatedAt = fixedInstant,
                testPeriod = ReportPeriod(fixedInstant, fixedInstant.plusSeconds(3600)),
                targetDevices = listOf(testDevice()),
                vulnerabilities = emptyList(),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
                executiveSummary = "Summary",
                findings = emptyList(),
                recommendations = emptyList(),
                appendix = ReportAppendix(
                    toolsUsed = listOf("BTSec TestTool"),
                    testMethodology = "OWASP",
                    limitations = emptyList(),
                    glossary = emptyMap(),
                    references = emptyList()
                ),
                status = ReportStatus.DRAFT
            )
            assertThat(report.id).isEqualTo("rpt-1")
            assertThat(report.title).isEqualTo("Test Report")
        }

        @Test
        @DisplayName("copy and toString")
        fun copyEtc() {
            val report = SecurityReport(
                id = "rpt-2",
                authId = "BTSEC-TEST",
                title = "Original",
                generatedAt = fixedInstant,
                testPeriod = ReportPeriod(fixedInstant, fixedInstant),
                targetDevices = emptyList(),
                vulnerabilities = emptyList(),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
                executiveSummary = "",
                findings = emptyList(),
                recommendations = emptyList(),
                appendix = ReportAppendix(emptyList(), "", emptyList(), emptyMap(), emptyList()),
                status = ReportStatus.FINAL
            )
            val copied = report.copy(title = "Updated")
            assertThat(copied.title).isEqualTo("Updated")
            assertThat(report.toString()).contains("id=")
        }
    }

    @Nested
    @DisplayName("ReportPeriod")
    inner class ReportPeriodTest {

        @Test
        @DisplayName("construction and equals")
        fun construction() {
            val period = ReportPeriod(fixedInstant, fixedInstant.plusSeconds(60))
            assertThat(period.start).isEqualTo(fixedInstant)
            val dup = period.copy()
            assertThat(period).isEqualTo(dup)
        }
    }

    @Nested
    @DisplayName("ReportFinding")
    inner class ReportFindingTest {

        @Test
        @DisplayName("construction")
        fun construction() {
            val finding = ReportFinding(
                category = FindingCategory.CRASH,
                severity = VulnerabilitySeverity.HIGH,
                count = 3,
                description = "3 crashes found",
                affectedDevices = listOf("AA:BB:CC:DD:EE:FF")
            )
            assertThat(finding.count).isEqualTo(3)
        }
    }

    @Nested
    @DisplayName("Recommendation")
    inner class RecommendationTest {

        @Test
        @DisplayName("construction")
        fun construction() {
            val rec = Recommendation(
                priority = RecommendationPriority.CRITICAL,
                title = "Update firmware",
                description = "Firmware is outdated",
                affectedDevices = listOf("AA:BB:CC:DD:EE:FF"),
                implementation = "Download latest firmware",
                verification = "Check firmware version"
            )
            assertThat(rec.priority).isEqualTo(RecommendationPriority.CRITICAL)
        }
    }

    @Nested
    @DisplayName("RecommendationPriority enum")
    inner class RecommendationPriorityTest {

        @Test
        @DisplayName("has expected values")
        fun values() {
            assertThat(RecommendationPriority.values()).asList().containsExactly(
                RecommendationPriority.CRITICAL, RecommendationPriority.HIGH,
                RecommendationPriority.MEDIUM, RecommendationPriority.LOW
            ).inOrder()
        }
    }

    @Nested
    @DisplayName("ReportAppendix")
    inner class ReportAppendixTest {

        @Test
        @DisplayName("construction and equals")
        fun construction() {
            val appendix = ReportAppendix(
                toolsUsed = listOf("tool1"),
                testMethodology = "method",
                limitations = listOf("lim1"),
                glossary = mapOf("BT" to "Bluetooth"),
                references = listOf("ref1")
            )
            val dup = appendix.copy()
            assertThat(appendix).isEqualTo(dup)
            assertThat(appendix.toString()).contains("toolsUsed=")
        }
    }

    @Nested
    @DisplayName("ReportStatus enum")
    inner class ReportStatusTest {

        @Test
        @DisplayName("has expected values")
        fun values() {
            assertThat(ReportStatus.values()).asList().containsExactly(
                ReportStatus.DRAFT, ReportStatus.REVIEW,
                ReportStatus.FINAL, ReportStatus.ARCHIVED
            ).inOrder()
        }
    }
}
