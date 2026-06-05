/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Room entity for [Authorization].
 */
@Entity(tableName = "authorizations")
data class AuthorizationEntity(
    @PrimaryKey
    @ColumnInfo(name = "auth_id")
    val authId: String,

    @ColumnInfo(name = "issued_to")
    val issuedTo: String,

    @ColumnInfo(name = "issued_by")
    val issuedBy: String,

    @ColumnInfo(name = "issued_at")
    val issuedAt: Long, // epoch millis

    @ColumnInfo(name = "expires_at")
    val expiresAt: Long, // epoch millis

    @ColumnInfo(name = "authorized_actions")
    val authorizedActions: String, // comma-separated TestAction enum names

    @ColumnInfo(name = "scope")
    val scope: String, // JSON of TestScope

    @ColumnInfo(name = "signature")
    val signature: String,

    @ColumnInfo(name = "terms")
    val terms: String, // JSON array of strings

    @ColumnInfo(name = "status")
    val status: String = "ACTIVE" // AuthorizationStatus enum name
)
