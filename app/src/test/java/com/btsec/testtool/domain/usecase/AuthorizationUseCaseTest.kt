/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.repository.AuthorizationRepository
import com.btsec.testtool.domain.repository.ConsentRepository
import io.mockk.mockk
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*

class AuthorizationUseCaseTest {

    private lateinit var useCase: AuthorizationUseCase
    private val authRepo: AuthorizationRepository = mockk(relaxed = true)
    private val consentRepo: ConsentRepository = mockk(relaxed = true)

    @Before
    fun setup() {
        useCase = AuthorizationUseCase(authRepo, consentRepo)
    }

    @Test
    fun `useCase is created successfully`() {
        assertNotNull(useCase)
    }
}
