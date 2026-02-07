/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.di

import com.btsec.testtool.data.authorization.AuthorizationRepositoryImpl
import com.btsec.testtool.data.bluetooth.BluetoothRepositoryImpl
import com.btsec.testtool.data.consent.ConsentRepositoryImpl
import com.btsec.testtool.data.fuzzing.FuzzingRepositoryImpl
import com.btsec.testtool.data.keyextraction.KeyExtractionRepositoryImpl
import com.btsec.testtool.data.report.ReportRepositoryImpl
import com.btsec.testtool.data.vulnerability.VulnerabilityRepositoryImpl
import com.btsec.testtool.domain.repository.AuthorizationRepository
import com.btsec.testtool.domain.repository.BluetoothRepository
import com.btsec.testtool.domain.repository.ConsentRepository
import com.btsec.testtool.domain.repository.FuzzingRepository
import com.btsec.testtool.domain.repository.KeyExtractionRepository
import com.btsec.testtool.domain.repository.ReportRepository
import com.btsec.testtool.domain.repository.VulnerabilityRepository
import com.btsec.testtool.domain.usecase.AuthorizationUseCase
import com.btsec.testtool.domain.usecase.BluetoothScanningUseCase
import com.btsec.testtool.domain.usecase.FuzzingUseCase
import com.btsec.testtool.domain.usecase.KeyExtractionUseCase
import com.btsec.testtool.domain.usecase.ReportGenerationUseCase
import com.btsec.testtool.domain.usecase.VulnerabilityScanningUseCase
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ViewModelComponent
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Hilt dependency injection module for repositories.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {

    @Binds
    @Singleton
    abstract fun bindAuthorizationRepository(
        impl: AuthorizationRepositoryImpl
    ): AuthorizationRepository

    @Binds
    @Singleton
    abstract fun bindBluetoothRepository(
        impl: BluetoothRepositoryImpl
    ): BluetoothRepository

    @Binds
    @Singleton
    abstract fun bindConsentRepository(
        impl: ConsentRepositoryImpl
    ): ConsentRepository

    @Binds
    @Singleton
    abstract fun bindFuzzingRepository(
        impl: FuzzingRepositoryImpl
    ): FuzzingRepository

    @Binds
    @Singleton
    abstract fun bindKeyExtractionRepository(
        impl: KeyExtractionRepositoryImpl
    ): KeyExtractionRepository

    @Binds
    @Singleton
    abstract fun bindReportRepository(
        impl: ReportRepositoryImpl
    ): ReportRepository

    @Binds
    @Singleton
    abstract fun bindVulnerabilityRepository(
        impl: VulnerabilityRepositoryImpl
    ): VulnerabilityRepository
}

/**
 * Hilt dependency injection module for use cases.
 */
@Module
@InstallIn(ViewModelComponent::class)
abstract class UseCaseModule {

    @Binds
    abstract fun bindAuthorizationUseCase(
        impl: AuthorizationUseCase
    ): AuthorizationUseCase

    @Binds
    abstract fun bindBluetoothScanningUseCase(
        impl: BluetoothScanningUseCase
    ): BluetoothScanningUseCase

    @Binds
    abstract fun bindFuzzingUseCase(
        impl: FuzzingUseCase
    ): FuzzingUseCase

    @Binds
    abstract fun bindKeyExtractionUseCase(
        impl: KeyExtractionUseCase
    ): KeyExtractionUseCase

    @Binds
    abstract fun bindReportGenerationUseCase(
        impl: ReportGenerationUseCase
    ): ReportGenerationUseCase

    @Binds
    abstract fun bindVulnerabilityScanningUseCase(
        impl: VulnerabilityScanningUseCase
    ): VulnerabilityScanningUseCase
}
