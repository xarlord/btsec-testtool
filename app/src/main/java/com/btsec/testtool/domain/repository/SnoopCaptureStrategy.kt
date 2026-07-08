/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import java.io.InputStream

/**
 * Strategy interface for reading HCI snoop log data.
 *
 * Each implementation provides a different way to access the btsnoop_hci.log
 * file on an Android device. The [SnoopCaptureRepositoryImpl] auto-selects
 * the first available strategy at runtime.
 *
 * Implementations:
 * - [com.btsec.testtool.data.bredr.strategy.DirectFileSnoopStrategy] — direct file read (requires root)
 * - [com.btsec.testtool.data.bredr.strategy.ShizukuSnoopStrategy] — Shizuku shell (root-free, requires Shizuku)
 * - [com.btsec.testtool.data.bredr.strategy.BugreportSnoopStrategy] — extract from ADB bugreport zip
 *
 * Issues: #375 (root-free snoop capture), #412 (strategy pattern refactor)
 */
interface SnoopCaptureStrategy {

    /**
     * Human-readable name of this strategy, e.g. "Direct File", "Shizuku".
     * Used for logging and UI display.
     */
    fun getName(): String

    /**
     * Check whether the underlying mechanism is available on this device.
     *
     * For example:
     * - DirectFileStrategy: always returns true (file may or may not exist yet)
     * - ShizukuSnoopStrategy: checks if Shizuku is installed and permission granted
     * - BugreportSnoopStrategy: always returns true (user provides a zip file)
     *
     * This should be a lightweight check (no I/O).
     */
    fun isAvailable(): Boolean

    /**
     * Check whether the snoop log is actually readable right now.
     *
     * This may involve I/O (e.g., checking file permissions, verifying
     * Shizuku service connectivity, or confirming a bugreport zip exists).
     *
     * @return true if the snoop log can be read immediately.
     */
    fun canReadSnoopLog(): Boolean

    /**
     * Open and return an [InputStream] to the snoop log data.
     *
     * The caller is responsible for closing the returned stream.
     *
     * @return [Result.success] containing the input stream, or
     *         [Result.failure] with the error that prevented reading.
     */
    fun readSnoopLog(): Result<InputStream>
}
