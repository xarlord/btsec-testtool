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
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Scanner
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
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
 * Responsive breakpoint thresholds (dp).
 */
private const val COMPACT_MAX_WIDTH = 599
private const val MEDIUM_MAX_WIDTH = 839

/**
 * Screen size classification for responsive layouts.
 */
private enum class WindowSizeClass { COMPACT, MEDIUM, EXPANDED }

/**
 * Dashboard Screen - Main hub for the application.
 *
 * This screen displays:
 * - Current authorization status
 * - Quick access to all features
 * - Navigation to feature screens
 *
 * Responsive layout (#136):
 * - Compact (phone portrait): Single column layout
 * - Medium (phone landscape/small tablet): Two-column feature grid
 * - Expanded (tablet): Three-column feature grid, side-by-side panels
 */
@Composable
fun DashboardScreen(
    authId: String,
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit,
    onNavigateToSettings: () -> Unit = {},
    onBack: () -> Unit
) {
    val configuration = LocalConfiguration.current
    val screenWidthDp = configuration.screenWidthDp
    val windowSize = when {
        screenWidthDp < COMPACT_MAX_WIDTH -> WindowSizeClass.COMPACT
        screenWidthDp < MEDIUM_MAX_WIDTH -> WindowSizeClass.MEDIUM
        else -> WindowSizeClass.EXPANDED
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.dashboard_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = stringResource(R.string.cd_navigate_back)
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = stringResource(R.string.cd_settings)
                        )
                    }
                }
            )
        }
    ) { padding ->
        when (windowSize) {
            WindowSizeClass.COMPACT -> CompactLayout(
                padding = padding,
                authId = authId,
                onNavigateToScanner = onNavigateToScanner,
                onNavigateToFuzzer = onNavigateToFuzzer,
                onNavigateToKeys = onNavigateToKeys,
                onNavigateToVulns = onNavigateToVulns,
                onNavigateToReports = onNavigateToReports
            )
            WindowSizeClass.MEDIUM -> MediumLayout(
                padding = padding,
                authId = authId,
                onNavigateToScanner = onNavigateToScanner,
                onNavigateToFuzzer = onNavigateToFuzzer,
                onNavigateToKeys = onNavigateToKeys,
                onNavigateToVulns = onNavigateToVulns,
                onNavigateToReports = onNavigateToReports
            )
            WindowSizeClass.EXPANDED -> ExpandedLayout(
                padding = padding,
                authId = authId,
                onNavigateToScanner = onNavigateToScanner,
                onNavigateToFuzzer = onNavigateToFuzzer,
                onNavigateToKeys = onNavigateToKeys,
                onNavigateToVulns = onNavigateToVulns,
                onNavigateToReports = onNavigateToReports
            )
        }
    }
}

// ════════════════════════════════════════════════════════
// Compact: phone portrait — single column
// ════════════════════════════════════════════════════════

@Composable
private fun CompactLayout(
    padding: PaddingValues,
    authId: String,
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        AuthorizationInfoCard(authId = authId)
        FeatureGridCompact(
            onNavigateToScanner = onNavigateToScanner,
            onNavigateToFuzzer = onNavigateToFuzzer,
            onNavigateToKeys = onNavigateToKeys,
            onNavigateToVulns = onNavigateToVulns,
            onNavigateToReports = onNavigateToReports
        )
    }
}

@Composable
private fun FeatureGridCompact(
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = stringResource(R.string.dashboard_features),
            style = MaterialTheme.typography.titleLarge
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            FeatureCard(
                icon = Icons.Filled.Scanner,
                title = stringResource(R.string.nav_scanner),
                description = stringResource(R.string.dashboard_scan_desc),
                onClick = onNavigateToScanner,
                modifier = Modifier.weight(1f)
            )
            FeatureCard(
                icon = Icons.Filled.BugReport,
                title = stringResource(R.string.nav_vulns),
                description = stringResource(R.string.dashboard_vulns_desc),
                onClick = onNavigateToVulns,
                modifier = Modifier.weight(1f)
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            FeatureCard(
                icon = Icons.Filled.Science,
                title = stringResource(R.string.nav_fuzzer),
                description = stringResource(R.string.dashboard_fuzz_desc),
                onClick = onNavigateToFuzzer,
                modifier = Modifier.weight(1f)
            )
            FeatureCard(
                icon = Icons.Filled.Key,
                title = stringResource(R.string.nav_keys),
                description = stringResource(R.string.dashboard_keys_desc),
                onClick = onNavigateToKeys,
                modifier = Modifier.weight(1f)
            )
        }

        FeatureCard(
            icon = Icons.Filled.Assessment,
            title = stringResource(R.string.nav_reports),
            description = stringResource(R.string.dashboard_reports_desc),
            onClick = onNavigateToReports,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

// ════════════════════════════════════════════════════════
// Medium: phone landscape / small tablet — two columns
// ════════════════════════════════════════════════════════

@Composable
private fun MediumLayout(
    padding: PaddingValues,
    authId: String,
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        AuthorizationInfoCard(authId = authId)
        FeatureGridTwoColumns(
            onNavigateToScanner = onNavigateToScanner,
            onNavigateToFuzzer = onNavigateToFuzzer,
            onNavigateToKeys = onNavigateToKeys,
            onNavigateToVulns = onNavigateToVulns,
            onNavigateToReports = onNavigateToReports
        )
    }
}

@Composable
private fun FeatureGridTwoColumns(
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = stringResource(R.string.dashboard_features),
            style = MaterialTheme.typography.titleLarge
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            FeatureCard(
                icon = Icons.Filled.Scanner,
                title = stringResource(R.string.nav_scanner),
                description = stringResource(R.string.dashboard_scan_desc),
                onClick = onNavigateToScanner,
                modifier = Modifier.weight(1f)
            )
            FeatureCard(
                icon = Icons.Filled.BugReport,
                title = stringResource(R.string.nav_vulns),
                description = stringResource(R.string.dashboard_vulns_desc),
                onClick = onNavigateToVulns,
                modifier = Modifier.weight(1f)
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            FeatureCard(
                icon = Icons.Filled.Science,
                title = stringResource(R.string.nav_fuzzer),
                description = stringResource(R.string.dashboard_fuzz_desc),
                onClick = onNavigateToFuzzer,
                modifier = Modifier.weight(1f)
            )
            FeatureCard(
                icon = Icons.Filled.Key,
                title = stringResource(R.string.nav_keys),
                description = stringResource(R.string.dashboard_keys_desc),
                onClick = onNavigateToKeys,
                modifier = Modifier.weight(1f)
            )
        }

        FeatureCard(
            icon = Icons.Filled.Assessment,
            title = stringResource(R.string.nav_reports),
            description = stringResource(R.string.dashboard_reports_desc),
            onClick = onNavigateToReports,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

// ════════════════════════════════════════════════════════
// Expanded: tablet — three+ columns, side-by-side panels
// ════════════════════════════════════════════════════════

@Composable
private fun ExpandedLayout(
    padding: PaddingValues,
    authId: String,
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(32.dp),
        horizontalArrangement = Arrangement.spacedBy(32.dp)
    ) {
        // Left panel: Authorization info
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxHeight(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            AuthorizationInfoCard(authId = authId)
        }

        // Right panel: Feature grid with 3-column layout
        Column(
            modifier = Modifier
                .weight(2.5f)
                .fillMaxHeight(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = stringResource(R.string.dashboard_features),
                style = MaterialTheme.typography.titleLarge
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                FeatureCard(
                    icon = Icons.Filled.Scanner,
                    title = stringResource(R.string.nav_scanner),
                    description = stringResource(R.string.dashboard_scan_desc),
                    onClick = onNavigateToScanner,
                    modifier = Modifier.weight(1f)
                )
                FeatureCard(
                    icon = Icons.Filled.BugReport,
                    title = stringResource(R.string.nav_vulns),
                    description = stringResource(R.string.dashboard_vulns_desc),
                    onClick = onNavigateToVulns,
                    modifier = Modifier.weight(1f)
                )
                FeatureCard(
                    icon = Icons.Filled.Science,
                    title = stringResource(R.string.nav_fuzzer),
                    description = stringResource(R.string.dashboard_fuzz_desc),
                    onClick = onNavigateToFuzzer,
                    modifier = Modifier.weight(1f)
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                FeatureCard(
                    icon = Icons.Filled.Key,
                    title = stringResource(R.string.nav_keys),
                    description = stringResource(R.string.dashboard_keys_desc),
                    onClick = onNavigateToKeys,
                    modifier = Modifier.weight(1f)
                )
                FeatureCard(
                    icon = Icons.Filled.Assessment,
                    title = stringResource(R.string.nav_reports),
                    description = stringResource(R.string.dashboard_reports_desc),
                    onClick = onNavigateToReports,
                    modifier = Modifier.weight(1f)
                )
                // Spacer to balance the 2-item row with the 3-item row above
                Spacer(modifier = Modifier.weight(1f))
            }
        }
    }
}

// ════════════════════════════════════════════════════════
// Shared components
// ════════════════════════════════════════════════════════

@Composable
private fun AuthorizationInfoCard(authId: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = stringResource(R.string.cd_authorization_status),
                tint = MaterialTheme.colorScheme.onPrimaryContainer
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text(
                    text = stringResource(R.string.dashboard_authorized),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
                Text(
                    text = stringResource(R.string.dashboard_auth_id_label, authId),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
            }
        }
    }
}

@Composable
private fun FeatureCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        onClick = onClick,
        modifier = modifier.height(120.dp)
    ) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                modifier = Modifier.size(32.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// ════════════════════════════════════════════════════════
// ViewModel
// ════════════════════════════════════════════════════════

/**
 * ViewModel for the Dashboard screen.
 */
@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val authorizationUseCase: AuthorizationUseCase
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
                    _uiState.value = _uiState.value.copy(
                        authId = it.authId,
                        isValid = true,
                        details = authorizationUseCase.getAuthorizationDetails()
                    )
                } ?: run {
                    _uiState.value = _uiState.value.copy(
                        authId = null,
                        isValid = false,
                        details = null
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
    val details: com.btsec.testtool.domain.usecase.AuthorizationDetails? = null
)


