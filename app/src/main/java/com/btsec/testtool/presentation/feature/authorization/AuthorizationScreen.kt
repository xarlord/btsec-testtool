/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.authorization

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.R
import com.btsec.testtool.domain.usecase.AuthorizationResult
import com.btsec.testtool.domain.usecase.AuthorizationUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Authorization Screen - Entry point for the application.
 *
 * This screen is responsible for:
 * - Displaying legal notices and warnings
 * - Collecting the authorization ID from the user
 * - Verifying the authorization with the backend
 * - Granting access to the main application
 *
 * Authorization ID format: BTSEC-YYYYMMDD-XXXXXXXX
 */
@Suppress("FunctionName")
@Composable
fun AuthorizationScreen(
    viewModel: AuthorizationViewModel = hiltViewModel(),
    onAuthorized: (String) -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()

    AuthorizationContent(
        authId = uiState.authId,
        authIdError = uiState.authIdError,
        isLoading = uiState.isLoading,
        error = uiState.error,
        onAuthIdChanged = viewModel::onAuthIdChanged,
        onVerifyAuthorization = { viewModel.verifyAuthorization(onAuthorized) },
        onSkipAuth = { onAuthorized("BTSEC-BYPASS-TESTMODE") },
    )
}

@Suppress("FunctionName")
@Composable
private fun AuthorizationContent(
    authId: String,
    authIdError: String?,
    isLoading: Boolean,
    error: String?,
    onAuthIdChanged: (String) -> Unit,
    onVerifyAuthorization: () -> Unit,
    onSkipAuth: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.authorization_title)) },
            )
        },
    ) { padding ->
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = "Application security icon",
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.error,
            )

            Text(
                text = stringResource(R.string.authorization_title),
                style = MaterialTheme.typography.headlineMedium,
            )

            Text(
                text = stringResource(R.string.authorization_description),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(modifier = Modifier.height(24.dp))

            val focusManager = LocalFocusManager.current

            OutlinedTextField(
                value = authId,
                onValueChange = onAuthIdChanged,
                label = { Text(stringResource(R.string.authorization_id_hint)) },
                placeholder = { Text("BTSEC-20260207-A1B2C3D4") },
                isError = authIdError != null,
                singleLine = true,
                trailingIcon = {
                    if (authId.isNotEmpty()) {
                        IconButton(onClick = {
                            onAuthIdChanged("")
                            focusManager.clearFocus()
                        }) {
                            Icon(
                                imageVector = Icons.Default.Cancel,
                                contentDescription = "Clear authorization ID"
                            )
                        }
                    }
                },
                keyboardOptions = KeyboardOptions(imeAction = androidx.compose.ui.text.input.ImeAction.Done),
                keyboardActions =
                    KeyboardActions(
                        onDone = {
                            focusManager.clearFocus()
                            if (authId.isNotBlank() && !isLoading) {
                                onVerifyAuthorization()
                            }
                        },
                    ),
                modifier = Modifier.fillMaxWidth(),
            )

            if (authIdError != null) {
                Text(
                    text = authIdError,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }

            Spacer(modifier = Modifier.weight(1f))

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors =
                    CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                    ),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = stringResource(R.string.legal_warning_title),
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = stringResource(R.string.legal_warning_text),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = onVerifyAuthorization,
                enabled = authId.isNotBlank() && !isLoading,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                } else {
                    Text(stringResource(R.string.authorization_verify))
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // BYPASS button — skip authorization for dev/testing
            Button(
                onClick = onSkipAuth,
                colors = androidx.compose.material3.ButtonDefaults.outlinedButtonColors(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("🚀 SKIP AUTHORIZATION (DEV MODE)")
            }

            if (error != null) {
                Text(
                    text = error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 16.dp),
                )
            }
        }
    }
}

/**
 * ViewModel for the Authorization screen.
 */
@HiltViewModel
class AuthorizationViewModel
    @Inject
    constructor(
        private val authorizationUseCase: AuthorizationUseCase,
    ) : ViewModel() {
        private val _uiState = MutableStateFlow(AuthorizationUiState())
        val uiState: StateFlow<AuthorizationUiState> = _uiState.asStateFlow()

        fun onAuthIdChanged(authId: String) {
            _uiState.value =
                _uiState.value.copy(
                    authId = authId.uppercase(),
                    authIdError = null,
                    error = null,
                )
        }

        fun verifyAuthorization(onAuthorized: (String) -> Unit) {
            val authId = _uiState.value.authId

            _uiState.value = _uiState.value.copy(isLoading = true)

            viewModelScope.launch {
                when (val result = authorizationUseCase.verifyAuthorization(authId)) {
                    is AuthorizationResult.Success -> {
                        _uiState.value =
                            _uiState.value.copy(
                                isLoading = false,
                                authId = authId,
                                authIdError = null,
                                error = null,
                            )
                        onAuthorized(authId)
                    }
                    is AuthorizationResult.Error -> {
                        _uiState.value =
                            _uiState.value.copy(
                                isLoading = false,
                                error = result.message,
                            )
                    }
                }
            }
        }
    }

/**
 * UI state for the Authorization screen.
 */
data class AuthorizationUiState(
    val authId: String = "",
    val authIdError: String? = null,
    val isLoading: Boolean = false,
    val error: String? = null,
)
