/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.content.Context
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.SdpEnumerationRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [SdpEnumerationRepository].
 *
 * Uses Android's BluetoothDevice.fetchUuidsWithSdp() for SDP service
 * discovery, and caches results in memory for quick retrieval.
 */
@Singleton
class SdpEnumerationRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : SdpEnumerationRepository {
        private val bluetoothManager: BluetoothManager =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

        private val isBrowsing = MutableStateFlow(false)
        private val cachedResults = MutableStateFlow<Map<String, SdpScanResult>>(emptyMap())

        @SuppressLint("MissingPermission")
        override fun browseServices(deviceAddress: String): Flow<SdpService> {
            return flow {
                isBrowsing.value = true
                try {
                    val device = bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                    if (device == null) {
                        Timber.w("Cannot get remote device: $deviceAddress")
                        return@flow
                    }

                    // Fetch UUIDs via SDP — this triggers asynchronous UUID discovery
                    val uuids = device.uuids ?: emptyArray()
                    val services = mutableListOf<SdpService>()

                    for (parcelUuid in uuids) {
                        val uuid = parcelUuid.uuid.toString().replace("-", "").uppercase()
                        val shortUuid = uuid.take(4)
                        val profile = BtProfile.fromUuid(shortUuid)

                        val service =
                            SdpService(
                                uuid = parcelUuid.uuid.toString(),
                                profile = profile,
                                name = profile.displayName,
                                rfcommChannel = null,
                                l2capPsm = null,
                                protocolDescriptors = emptyList(),
                                requiresAuthentication = null,
                                requiresEncryption = null,
                                version = null,
                                providerName = null,
                                serviceName = profile.displayName,
                                isHidden = false,
                                securityRisk = SecurityRisk.UNKNOWN,
                            )
                        services.add(service)
                        emit(service)
                    }

                    // Cache the result
                    val scanResult =
                        SdpScanResult(
                            deviceAddress = deviceAddress,
                            deviceName = device.name,
                            services = services,
                            hiddenServices = emptyList(),
                            securityIssues = emptyList(),
                            scanDurationMs = 0L,
                        )
                    saveScanResult(scanResult)
                } catch (e: SecurityException) {
                    Timber.e(e, "Missing Bluetooth permissions for SDP browse")
                } catch (e: Exception) {
                    Timber.e(e, "SDP browse failed for $deviceAddress")
                } finally {
                    isBrowsing.value = false
                }
            }
        }

        override suspend fun getCachedScanResult(deviceAddress: String): SdpScanResult? {
            return cachedResults.value[deviceAddress]
        }

        override fun getAllScanResults(): Flow<List<SdpScanResult>> {
            return cachedResults.map { it.values.toList() }
        }

        override suspend fun saveScanResult(result: SdpScanResult) {
            val updated = cachedResults.value.toMutableMap()
            updated[result.deviceAddress] = result
            cachedResults.value = updated
        }

        override suspend fun deleteScanResult(deviceAddress: String) {
            val updated = cachedResults.value.toMutableMap()
            updated.remove(deviceAddress)
            cachedResults.value = updated
        }

        override fun isBrowsing(): Flow<Boolean> {
            return isBrowsing
        }
    }
