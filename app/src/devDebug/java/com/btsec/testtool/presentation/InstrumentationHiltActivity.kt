/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation

import androidx.activity.ComponentActivity
import dagger.hilt.android.AndroidEntryPoint

/**
 * Empty Hilt-enabled host for dev-debug Compose instrumentation tests.
 *
 * It deliberately does not call setContent(), allowing Compose test rules to
 * install the screen under test while sharing the target app's Hilt graph.
 */
@AndroidEntryPoint
class InstrumentationHiltActivity : ComponentActivity()
