/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

/**
 * Main ViewModel for managing application-wide state.
 *
 * This includes permission state, navigation state, and global UI state.
 */
@HiltViewModel
class MainViewModel
    @Inject
    constructor() : ViewModel() {
        // Permission state
        private val _hasRequiredPermissions = MutableStateFlow(false)
        val hasRequiredPermissions: StateFlow<Boolean> = _hasRequiredPermissions.asStateFlow()

        // Loading state
        private val _isLoading = MutableStateFlow(false)
        val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

        init {
            Timber.d("MainViewModel initialized")
        }

        /**
         * Handle permission request results.
         *
         * @param allGranted True if all permissions were granted
         */
        fun onPermissionResult(allGranted: Boolean) {
            viewModelScope.launch {
                _hasRequiredPermissions.value = allGranted
                Timber.d("Permission result: allGranted=$allGranted")
            }
        }

        /**
         * Update loading state.
         *
         * @param loading True if loading
         */
        fun setLoading(loading: Boolean) {
            _isLoading.value = loading
        }

        override fun onCleared() {
            super.onCleared()
            Timber.d("MainViewModel cleared")
        }
    }
