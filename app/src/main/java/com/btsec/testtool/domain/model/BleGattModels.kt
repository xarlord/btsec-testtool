/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import kotlinx.serialization.Serializable

/**
 * BLE Service information.
 */
@Serializable
data class BleService(
    val uuid: String,                  // Service UUID
    val primary: Boolean,              // Is primary service
    val characteristics: List<BleCharacteristic> = emptyList()
)

/**
 * BLE Characteristic information.
 */
@Serializable
data class BleCharacteristic(
    val uuid: String,                  // Characteristic UUID
    val properties: CharacteristicProperties,  // Read/write/notify properties
    val permissions: CharacteristicPermissions?,  // Permissions
    @Serializable(with = ByteArraySerializer::class)
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
@Serializable
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
@Serializable
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
@Serializable
data class BleDescriptor(
    val uuid: String,
    @Serializable(with = ByteArraySerializer::class)
    val value: ByteArray? = null
)
