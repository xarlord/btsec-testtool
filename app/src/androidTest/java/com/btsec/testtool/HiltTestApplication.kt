/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool

import android.app.Application
import dagger.hilt.android.testing.CustomTestApplication

/**
 * Hilt test application for instrumented tests.
 * Uses the production BtSecTestToolApplication as base.
 */
@CustomTestApplication(BtSecTestToolApplication::class)
interface HiltTestApplication
