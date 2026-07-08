/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.di

import com.btsec.testtool.data.bredr.strategy.BugreportSnoopStrategy
import com.btsec.testtool.data.bredr.strategy.DirectFileSnoopStrategy
import com.btsec.testtool.data.bredr.strategy.ShizukuSnoopStrategy
import com.btsec.testtool.domain.repository.SnoopCaptureStrategy
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.ElementsIntoSet

/**
 * Hilt module that provides the ordered set of [SnoopCaptureStrategy] implementations.
 *
 * Strategies are injected into [SnoopCaptureRepositoryImpl] as a `List<SnoopCaptureStrategy>`.
 * The repository iterates through them to find the first available one.
 *
 * The order matters: strategies listed first are preferred. Currently:
 * 1. DirectFileStrategy — tried first (works on rooted devices)
 * 2. ShizukuStrategy — root-free when Shizuku is installed (placeholder)
 * 3. BugreportStrategy — root-free post-capture analysis
 *
 * To change priority, reorder the `@Provides` methods below.
 *
 * Issues: #375 (root-free snoop capture), #412 (strategy pattern refactor)
 */
@Module
@InstallIn(SingletonComponent::class)
object SnoopStrategyModule {

    @ElementsIntoSet
    @JvmStatic
    fun provideDirectFileStrategy(strategy: DirectFileSnoopStrategy): Set<SnoopCaptureStrategy> =
        setOf(strategy)

    @ElementsIntoSet
    @JvmStatic
    fun provideShizukuStrategy(strategy: ShizukuSnoopStrategy): Set<SnoopCaptureStrategy> =
        setOf(strategy)

    @ElementsIntoSet
    @JvmStatic
    fun provideBugreportStrategy(strategy: BugreportSnoopStrategy): Set<SnoopCaptureStrategy> =
        setOf(strategy)
}
