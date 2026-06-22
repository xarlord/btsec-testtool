/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.repository.AuthorizationRepository
import com.btsec.testtool.domain.repository.ConsentRepository
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AuthorizationUseCaseTest {
    private lateinit var useCase: AuthorizationUseCase
    private val authRepo: AuthorizationRepository = mockk(relaxed = true)
    private val consentRepo: ConsentRepository = mockk(relaxed = true)

    @BeforeEach
    fun setup() {
        useCase = AuthorizationUseCase(authRepo, consentRepo)
    }

    @Test
    fun `useCase is created successfully`() {
        assertNotNull(useCase)
    }
}
