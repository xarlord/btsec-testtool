/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.dashboard

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Scanner
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.R
import com.btsec.testtool.domain.usecase.AuthorizationUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Dashboard Screen - Main hub for the application.
 *
 * This screen displays:
 * - Current authorization status
 * - Quick access to all features
 * - Navigation to feature screens
 */
@Composable
fun DashboardScreen(
    authId: String,
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.dashboard_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Navigate back",
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            AuthorizationInfoCard(authId = authId)
            FeatureGrid(
                onNavigateToScanner = onNavigateToScanner,
                onNavigateToFuzzer = onNavigateToFuzzer,
                onNavigateToKeys = onNavigateToKeys,
                onNavigateToVulns = onNavigateToVulns,
                onNavigateToReports = onNavigateToReports,
            )
        }
    }
}

@Composable
private fun AuthorizationInfoCard(authId: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors =
            CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
            ),
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = "Authorization Status Icon",
                tint = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text(
                    text = "Authorized",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
                Text(
                    text = "Authorization ID: $authId",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            }
        }
    }
}

@Composable
private fun FeatureGrid(
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Features",
            style = MaterialTheme.typography.titleLarge,
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            FeatureCard(
                icon = Icons.Filled.Scanner,
                title = stringResource(R.string.nav_scanner),
                description = "Scan for Bluetooth devices",
                onClick = onNavigateToScanner,
                modifier = Modifier.weight(1f),
            )
            FeatureCard(
                icon = Icons.Filled.BugReport,
                title = stringResource(R.string.nav_vulns),
                description = "Scan for vulnerabilities",
                onClick = onNavigateToVulns,
                modifier = Modifier.weight(1f),
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            FeatureCard(
                icon = Icons.Filled.Science,
                title = stringResource(R.string.nav_fuzzer),
                description = "Fuzz Bluetooth protocols",
                onClick = onNavigateToFuzzer,
                modifier = Modifier.weight(1f),
            )
            FeatureCard(
                icon = Icons.Filled.Key,
                title = stringResource(R.string.nav_keys),
                description = "Extract Bluetooth keys",
                onClick = onNavigateToKeys,
                modifier = Modifier.weight(1f),
            )
        }

        FeatureCard(
            icon = Icons.Filled.Assessment,
            title = stringResource(R.string.nav_reports),
            description = "View and generate reports",
            onClick = onNavigateToReports,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun FeatureCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        onClick = onClick,
        modifier = modifier.height(120.dp),
    ) {
        Column(
            modifier =
                Modifier
                    .padding(16.dp)
                    .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                modifier = Modifier.size(32.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * ViewModel for the Dashboard screen.
 */
@HiltViewModel
class DashboardViewModel
    @Inject
    constructor(
        private val authorizationUseCase: AuthorizationUseCase,
    ) : ViewModel() {
        private val _uiState = MutableStateFlow(DashboardUiState())
        val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

        init {
            loadAuthorizationDetails()
        }

        private fun loadAuthorizationDetails() {
            viewModelScope.launch {
                authorizationUseCase.getCurrentAuthorization().collect { auth ->
                    auth?.let {
                        _uiState.value =
                            _uiState.value.copy(
                                authId = it.authId,
                                isValid = true,
                                details = authorizationUseCase.getAuthorizationDetails(),
                            )
                    } ?: run {
                        _uiState.value =
                            _uiState.value.copy(
                                authId = null,
                                isValid = false,
                                details = null,
                            )
                    }
                }
            }
        }

        fun refreshAuthorization() {
            loadAuthorizationDetails()
        }
    }

/**
 * UI state for the Dashboard screen.
 */
data class DashboardUiState(
    val authId: String? = null,
    val isValid: Boolean = false,
    val details: com.btsec.testtool.domain.usecase.AuthorizationDetails? = null,
)
