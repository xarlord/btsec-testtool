/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.authorization

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.R
import com.btsec.testtool.domain.usecase.AuthorizationUseCase
import com.btsec.testtool.domain.usecase.AuthorizationResult
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

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
@Composable
fun AuthorizationScreen(
    viewModel: AuthorizationViewModel = hiltViewModel(),
    onAuthorized: (String) -> Unit
) {
    val uiState by viewModel.uiState.collectAsState()

    AuthorizationContent(
        authId = uiState.authId,
        authIdError = uiState.authIdError,
        isLoading = uiState.isLoading,
        error = uiState.error,
        onAuthIdChanged = viewModel::onAuthIdChanged,
        onVerifyAuthorization = { viewModel.verifyAuthorization(onAuthorized) }
    )
}

@Composable
private fun AuthorizationContent(
    authId: String,
    authIdError: String?,
    isLoading: Boolean,
    error: String?,
    onAuthIdChanged: (String) -> Unit,
    onVerifyAuthorization: () -> Unit
) {
    val focusManager = LocalFocusManager.current

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = { Text(stringResource(R.string.authorization_title)) }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.error
            )

            Text(
                text = stringResource(R.string.authorization_title),
                style = MaterialTheme.typography.headlineMedium
            )

            Text(
                text = stringResource(R.string.authorization_description),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(24.dp))

            OutlinedTextField(
                value = authId,
                onValueChange = onAuthIdChanged,
                label = { Text(stringResource(R.string.authorization_id_hint)) },
                placeholder = { Text("BTSEC-20260207-A1B2C3D4") },
                isError = authIdError != null,
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.Characters,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(
                    onDone = {
                        focusManager.clearFocus()
                        if (authId.isNotBlank() && !isLoading) {
                            onVerifyAuthorization()
                        }
                    }
                ),
                modifier = Modifier.fillMaxWidth()
            )

            if (authIdError != null) {
                Text(
                    text = authIdError,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }

            Spacer(modifier = Modifier.weight(1f))

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = stringResource(R.string.legal_warning_title),
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = stringResource(R.string.legal_warning_text),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = onVerifyAuthorization,
                enabled = authId.isNotBlank() && !isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                } else {
                    Text(stringResource(R.string.authorization_verify))
                }
            }

            if (error != null) {
                Text(
                    text = error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 16.dp)
                )
            }
        }
    }
}

/**
 * ViewModel for the Authorization screen.
 */
@HiltViewModel
class AuthorizationViewModel @Inject constructor(
    private val authorizationUseCase: AuthorizationUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(AuthorizationUiState())
    val uiState: StateFlow<AuthorizationUiState> = _uiState.asStateFlow()

    fun onAuthIdChanged(authId: String) {
        _uiState.value = _uiState.value.copy(
            authId = authId.uppercase(),
            authIdError = null,
            error = null
        )
    }

    fun verifyAuthorization(onAuthorized: (String) -> Unit) {
        val authId = _uiState.value.authId

        _uiState.value = _uiState.value.copy(isLoading = true)

        viewModelScope.launch {
            when (val result = authorizationUseCase.verifyAuthorization(authId)) {
                is AuthorizationResult.Success -> {
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        authId = authId,
                        authIdError = null,
                        error = null
                    )
                    onAuthorized(authId)
                }
                is AuthorizationResult.Error -> {
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        error = result.message
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
    val error: String? = null
)
