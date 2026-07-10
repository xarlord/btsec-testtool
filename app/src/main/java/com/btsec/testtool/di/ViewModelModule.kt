/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.di

import com.btsec.testtool.data.bluetooth.BluetoothRepositoryImpl
import com.btsec.testtool.data.bredr.AvrcpSecurityRepositoryImpl
import com.btsec.testtool.data.bredr.HfpSecurityRepositoryImpl
import com.btsec.testtool.data.bredr.L2capSecurityRepositoryImpl
import com.btsec.testtool.data.bredr.MapSecurityRepositoryImpl
import com.btsec.testtool.data.bredr.PbapSecurityRepositoryImpl
import com.btsec.testtool.data.bredr.RfcommFuzzingRepositoryImpl
import com.btsec.testtool.data.bredr.SapSecurityRepositoryImpl
import com.btsec.testtool.data.bredr.SdpEnumerationRepositoryImpl
import com.btsec.testtool.data.bredr.SnoopCaptureRepositoryImpl
import com.btsec.testtool.data.fuzzing.FuzzingRepositoryImpl
import com.btsec.testtool.data.keyextraction.KeyExtractionRepositoryImpl
import com.btsec.testtool.data.report.ReportRepositoryImpl
import com.btsec.testtool.data.vulnerability.ProductionBtProbe
import com.btsec.testtool.data.vulnerability.VulnerabilityProbe
import com.btsec.testtool.data.vulnerability.VulnerabilityRepositoryImpl
import com.btsec.testtool.domain.repository.AvrcpSecurityRepository
import com.btsec.testtool.domain.repository.BluetoothOperationsWriter
import com.btsec.testtool.domain.repository.BluetoothRepository
import com.btsec.testtool.domain.repository.BluetoothStateReader
import com.btsec.testtool.domain.repository.FuzzingReader
import com.btsec.testtool.domain.repository.FuzzingRepository
import com.btsec.testtool.domain.repository.FuzzingWriter
import com.btsec.testtool.domain.repository.HfpSecurityRepository
import com.btsec.testtool.domain.repository.KeyExtractionReader
import com.btsec.testtool.domain.repository.KeyExtractionRepository
import com.btsec.testtool.domain.repository.KeyExtractionWriter
import com.btsec.testtool.domain.repository.L2capSecurityRepository
import com.btsec.testtool.domain.repository.MapSecurityRepository
import com.btsec.testtool.domain.repository.PbapSecurityRepository
import com.btsec.testtool.domain.repository.ReportReader
import com.btsec.testtool.domain.repository.ReportRepository
import com.btsec.testtool.domain.repository.ReportWriter
import com.btsec.testtool.domain.repository.RfcommFuzzingRepository
import com.btsec.testtool.domain.repository.SapSecurityRepository
import com.btsec.testtool.domain.repository.SdpEnumerationRepository
import com.btsec.testtool.domain.repository.SnoopCaptureRepository
import com.btsec.testtool.domain.repository.VulnerabilityReader
import com.btsec.testtool.domain.repository.VulnerabilityRepository
import com.btsec.testtool.domain.repository.VulnerabilityWriter
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
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
    abstract fun bindBluetoothRepository(impl: BluetoothRepositoryImpl): BluetoothRepository

    // Segregated sub-interfaces (ISP) — bound to the same impl so narrow
    // read/write contracts can be injected without depending on the full
    // repository.
    @Binds
    @Singleton
    abstract fun bindBluetoothStateReader(impl: BluetoothRepositoryImpl): BluetoothStateReader

    @Binds
    @Singleton
    abstract fun bindBluetoothOperationsWriter(impl: BluetoothRepositoryImpl): BluetoothOperationsWriter

    @Binds
    @Singleton
    abstract fun bindFuzzingRepository(impl: FuzzingRepositoryImpl): FuzzingRepository

    @Binds
    @Singleton
    abstract fun bindFuzzingReader(impl: FuzzingRepositoryImpl): FuzzingReader

    @Binds
    @Singleton
    abstract fun bindFuzzingWriter(impl: FuzzingRepositoryImpl): FuzzingWriter

    @Binds
    @Singleton
    abstract fun bindKeyExtractionRepository(impl: KeyExtractionRepositoryImpl): KeyExtractionRepository

    @Binds
    @Singleton
    abstract fun bindKeyExtractionReader(impl: KeyExtractionRepositoryImpl): KeyExtractionReader

    @Binds
    @Singleton
    abstract fun bindKeyExtractionWriter(impl: KeyExtractionRepositoryImpl): KeyExtractionWriter

    @Binds
    @Singleton
    abstract fun bindReportRepository(impl: ReportRepositoryImpl): ReportRepository

    @Binds
    @Singleton
    abstract fun bindReportReader(impl: ReportRepositoryImpl): ReportReader

    @Binds
    @Singleton
    abstract fun bindReportWriter(impl: ReportRepositoryImpl): ReportWriter

    @Binds
    @Singleton
    abstract fun bindVulnerabilityRepository(impl: VulnerabilityRepositoryImpl): VulnerabilityRepository

    @Binds
    @Singleton
    abstract fun bindVulnerabilityReader(impl: VulnerabilityRepositoryImpl): VulnerabilityReader

    @Binds
    @Singleton
    abstract fun bindVulnerabilityWriter(impl: VulnerabilityRepositoryImpl): VulnerabilityWriter

    @Binds
    @Singleton
    abstract fun bindVulnerabilityProbe(impl: ProductionBtProbe): VulnerabilityProbe

    // ========== BR/EDR Profile Repositories (#331) ==========

    @Binds
    @Singleton
    abstract fun bindSdpEnumerationRepository(impl: SdpEnumerationRepositoryImpl): SdpEnumerationRepository

    @Binds
    @Singleton
    abstract fun bindRfcommFuzzingRepository(impl: RfcommFuzzingRepositoryImpl): RfcommFuzzingRepository

    @Binds
    @Singleton
    abstract fun bindHfpSecurityRepository(impl: HfpSecurityRepositoryImpl): HfpSecurityRepository

    @Binds
    @Singleton
    abstract fun bindAvrcpSecurityRepository(impl: AvrcpSecurityRepositoryImpl): AvrcpSecurityRepository

    @Binds
    @Singleton
    abstract fun bindPbapSecurityRepository(impl: PbapSecurityRepositoryImpl): PbapSecurityRepository

    @Binds
    @Singleton
    abstract fun bindMapSecurityRepository(impl: MapSecurityRepositoryImpl): MapSecurityRepository

    @Binds
    @Singleton
    abstract fun bindSapSecurityRepository(impl: SapSecurityRepositoryImpl): SapSecurityRepository

    @Binds
    @Singleton
    abstract fun bindL2capSecurityRepository(impl: L2capSecurityRepositoryImpl): L2capSecurityRepository

    @Binds
    @Singleton
    abstract fun bindSnoopCaptureRepository(impl: SnoopCaptureRepositoryImpl): SnoopCaptureRepository
}

/**
 * Hilt dependency injection module for use cases.
 *
 * NOTE: UseCaseModule has been removed because all use cases are concrete classes
 * with @Inject constructors. Hilt can automatically provide them without @Binds methods.
 * @Binds is only needed when binding an interface to an implementation.
 */
