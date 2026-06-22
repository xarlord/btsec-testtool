/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.btsec.testtool.data.local.entity.AuthorizationEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for Authorization CRUD and scope queries.
 */
@Dao
interface AuthorizationDao {
    // ========== Authorization CRUD ==========

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAuthorization(authorization: AuthorizationEntity)

    @Update
    suspend fun updateAuthorization(authorization: AuthorizationEntity)

    @Delete
    suspend fun deleteAuthorization(authorization: AuthorizationEntity)

    @Query("DELETE FROM authorizations WHERE auth_id = :authId")
    suspend fun deleteAuthorizationById(authId: String)

    @Query("DELETE FROM authorizations")
    suspend fun deleteAllAuthorizations()

    @Query("SELECT * FROM authorizations WHERE auth_id = :authId")
    suspend fun getAuthorizationById(authId: String): AuthorizationEntity?

    @Query("SELECT * FROM authorizations ORDER BY issued_at DESC")
    fun getAllAuthorizations(): Flow<List<AuthorizationEntity>>

    @Query("SELECT * FROM authorizations WHERE status = :status")
    fun getAuthorizationsByStatus(status: String): Flow<List<AuthorizationEntity>>

    // ========== Scope Queries ==========

    @Query("SELECT * FROM authorizations WHERE auth_id = :authId AND status = 'ACTIVE'")
    suspend fun getActiveAuthorization(authId: String): AuthorizationEntity?

    @Query("SELECT * FROM authorizations WHERE status = 'ACTIVE' LIMIT 1")
    fun getCurrentActiveAuthorization(): Flow<AuthorizationEntity?>

    @Query("SELECT * FROM authorizations WHERE expires_at > :nowEpochMs AND status = 'ACTIVE'")
    fun getValidAuthorizations(nowEpochMs: Long): Flow<List<AuthorizationEntity>>

    @Query("SELECT * FROM authorizations WHERE expires_at <= :nowEpochMs AND status = 'ACTIVE'")
    fun getExpiredAuthorizations(nowEpochMs: Long): Flow<List<AuthorizationEntity>>

    @Query("SELECT * FROM authorizations WHERE authorized_actions LIKE '%' || :action || '%'")
    fun getAuthorizationsWithAction(action: String): Flow<List<AuthorizationEntity>>

    @Query("UPDATE authorizations SET status = :status WHERE auth_id = :authId")
    suspend fun updateAuthorizationStatus(
        authId: String,
        status: String,
    )

    @Query("SELECT COUNT(*) FROM authorizations")
    suspend fun getAuthorizationCount(): Int
}
