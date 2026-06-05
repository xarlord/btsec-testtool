/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.google.devtools.ksp")
    id("com.google.dagger.hilt.android")
    id("jacoco")
    id("org.owasp.dependencycheck")
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "com.btsec.testtool"
    compileSdk = Versions.compileSdk

    defaultConfig {
        applicationId = "com.btsec.testtool"
        minSdk = Versions.minSdk
        targetSdk = Versions.targetSdk
        versionCode = Versions.versionCode
        versionName = Versions.versionName

        // Test instrumentation
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["clearPackageData"] = "true"

        // Vector drawable support
        vectorDrawables.useSupportLibrary = true

        // Multi-dex (for older Android versions)
        multiDexEnabled = true

        // Build configuration fields
        buildConfigField("String", "VERSION_NAME", "\"${Versions.versionName}\"")
        buildConfigField("int", "VERSION_CODE", "${Versions.versionCode}")
        buildConfigField("String", "BUILD_TIME", "\"${System.currentTimeMillis()}\"")

        // ProGuard rules
        proguardFiles(
            getDefaultProguardFile("proguard-android-optimize.txt"),
            "proguard-rules.pro"
        )
    }

    signingConfigs {
        create("release") {
            // Release signing configuration
            // For production, create a keystore and configure here
            // DO NOT commit real signing credentials to source control
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"

            isDebuggable = true
            isMinifyEnabled = false

            // BuildConfig fields for debug builds
            buildConfigField("boolean", "DEBUG_MODE", "true")
            buildConfigField("boolean", "ENABLE_LOGGING", "true")
        }

        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )

            // BuildConfig fields for release builds
            buildConfigField("boolean", "DEBUG_MODE", "false")
            buildConfigField("boolean", "ENABLE_LOGGING", "false")
        }
    }

    flavorDimensions += listOf("environment")
    productFlavors {
        create("dev") {
            dimension = "environment"
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
            buildConfigField("String", "ENVIRONMENT", "\"dev\"")
        }
        create("prod") {
            dimension = "environment"
            buildConfigField("String", "ENVIRONMENT", "\"prod\"")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf(
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=androidx.compose.foundation.ExperimentalFoundationApi",
            "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi",
            "-opt-in=kotlinx.coroutines.FlowPreview"
        )
    }

    buildFeatures {
        compose = true
        buildConfig = true
        aidl = false
        renderScript = false
        shaders = false
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.6"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/LICENSE*"
            excludes += "/META-INF/NOTICE*"
            excludes += "META-INF/*.kotlin_module"
            excludes += "**/attach_hotspot_windows.dll"
            excludes += "META-INF/licenses/ASM"
            excludes += "META-INF/licenses/gradle-plugin*"
            excludes += "META-INF/INDEX.LIST"
            excludes += "META-INF/io.netty.versions.properties"
        }
        jniLibs {
            useLegacyPackaging = false
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
        animationsDisabled = true
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/java")
            kotlin.srcDirs("src/main/kotlin")
            res.srcDirs("src/main/res")
            assets.srcDirs("src/main/assets")
        }
        getByName("test") {
            java.srcDirs("src/test/java")
            kotlin.srcDirs("src/test/kotlin")
            res.srcDirs("src/test/res")
        }
        getByName("androidTest") {
            java.srcDirs("src/androidTest/java")
            kotlin.srcDirs("src/androidTest/kotlin")
            res.srcDirs("src/androidTest/res")
        }
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = true
        checkAllWarnings = true
        warningsAsErrors = false
        disable += setOf(
            "GradleDependency",
            "OldTargetApi",
            "IconDuplicates",
            "IconLocation",
            "GoogleAppIndexingWarning"
        )
        baseline = file("lint-baseline.xml")
    }
}

// Jacoco Test Coverage Configuration
tasks.register<JacocoReport>("jacocoTestReport") {
    dependsOn("testDevDebugUnitTest")

    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(false)
    }

    val fileFilter = listOf(
        "**/R.class",
        "**/R$*.class",
        "**/BuildConfig.*",
        "**/Manifest*.*",
        "**/*Test*.*",
        "android/**/*.*",
        "**/databinding/**",
        "**/android/databinding/**",
        "**/androidx/databinding/**",
        "**/*_Factory.class",
        "**/*_MembersInjector.class",
        "**/Dagger*Component*.*",
        "**/*Hilt*.*",
        "**/*DI*.*",
        "**/di/**"
    )

    val debugTree = fileTree("${buildDir}/tmp/kotlin-classes/debug") {
        exclude(fileFilter)
    }

    val mainSrc = "${project.projectDir}/src/main/java"
    val mainKotlinSrc = "${project.projectDir}/src/main/kotlin"

    sourceDirectories.setFrom(files(listOf(mainSrc, mainKotlinSrc)))
    classDirectories.setFrom(files(listOf(debugTree)))
    executionData.setFrom(fileTree(buildDir) {
        include(listOf("**/*.exec", "**/*.ec"))
    })
}

dependencies {
    // Core Android
    implementation("androidx.core:core-ktx:${Versions.coreKtx}")
    implementation("androidx.appcompat:appcompat:${Versions.appcompat}")
    implementation("androidx.activity:activity-compose:${Versions.activity}")
    implementation("androidx.activity:activity-ktx:${Versions.activity}")

    // Lifecycle
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:${Versions.lifecycle}")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:${Versions.lifecycle}")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:${Versions.lifecycle}")
    implementation("androidx.lifecycle:lifecycle-viewmodel-savedstate:${Versions.lifecycle}")

    // Navigation
    implementation("androidx.navigation:navigation-compose:${Versions.navigation}")

    // Compose BOM
    implementation(platform("androidx.compose:compose-bom:${Versions.composeBom}"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.animation:animation")

    // Constraint Layout Compose
    implementation("androidx.constraintlayout:constraintlayout-compose:${Versions.constraintLayout}")

    // Accompanist
    implementation("com.google.accompanist:accompanist-permissions:${Versions.accompanist}")
    implementation("com.google.accompanist:accompanist-systemuicontroller:${Versions.accompanist}")
    implementation("com.google.accompanist:accompanist-swiperefresh:${Versions.accompanist}")
    implementation("com.google.accompanist:accompanist-flowlayout:${Versions.accompanist}")

    // Dependency Injection
    implementation("com.google.dagger:hilt-android:${Versions.hilt}")
    ksp("com.google.dagger:hilt-compiler:${Versions.hilt}")
    implementation("androidx.hilt:hilt-navigation-compose:${Versions.hiltNavigationCompose}")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:${Versions.kotlinCoroutines}")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.kotlinCoroutines}")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-jdk8:${Versions.kotlinCoroutines}")

    // Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:${Versions.kotlinSerialization}")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-protobuf:${Versions.kotlinSerialization}")

    // Immutable collections
    implementation("org.jetbrains.kotlinx:kotlinx-collections-immutable:${Versions.kotlinImmutable}")

    // Room Database
    implementation("androidx.room:room-runtime:${Versions.room}")
    implementation("androidx.room:room-ktx:${Versions.room}")
    ksp("androidx.room:room-compiler:${Versions.room}")

    // DataStore
    implementation("androidx.datastore:datastore-preferences:${Versions.dataStore}")

    // Security
    implementation("androidx.security:security-crypto:${Versions.security}")

    // Work Manager
    implementation("androidx.work:work-runtime-ktx:${Versions.work}")
    implementation("androidx.hilt:hilt-work:${Versions.hiltWork}")
    ksp("androidx.hilt:hilt-compiler:${Versions.hiltAndroidX}")

    // Startup
    implementation("androidx.startup:startup-runtime:${Versions.startup}")

    // Network
    implementation("com.squareup.okhttp3:okhttp:${Versions.okhttp}")
    implementation("com.squareup.okhttp3:logging-interceptor:${Versions.okhttpLogging}")
    implementation("com.squareup.retrofit2:retrofit:${Versions.retrofit}")
    implementation("com.jakewharton.retrofit:retrofit2-kotlinx-serialization-converter:${Versions.retrofitSerialization}")

    // Protobuf
    implementation("com.google.protobuf:protobuf-kotlin-lite:${Versions.protobufKotlinLite}")

    // PDF Generation
    implementation("com.itextpdf:kernel:${Versions.iText7}")
    implementation("com.itextpdf:io:${Versions.iText7}")
    implementation("com.itextpdf:layout:${Versions.iText7}")

    // Logging
    implementation("com.jakewharton.timber:timber:${Versions.timber}")

    // Debugging
    debugImplementation("com.squareup.leakcanary:leakcanary-android:${Versions.leakCanary}")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:${Versions.junitJupiter}")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:${Versions.kotlinCoroutines}")
    testImplementation("io.mockk:mockk:${Versions.mockk}")
    testImplementation("app.cash.turbine:turbine:${Versions.turbine}")
    testImplementation("com.google.truth:truth:${Versions.truth}")
    testImplementation("org.robolectric:robolectric:${Versions.robolectric}")

    // Android Testing
    androidTestImplementation("androidx.test.ext:junit:${Versions.androidxJunit}")
    androidTestImplementation("androidx.test.espresso:espresso-core:${Versions.espresso}")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4:${Versions.composeTesting}")
    androidTestImplementation("com.google.dagger:hilt-android-testing:${Versions.hilt}")
    kspAndroidTest("com.google.dagger:hilt-compiler:${Versions.hilt}")
    androidTestImplementation("io.mockk:mockk-android:${Versions.mockk}")

    // Debug
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

// OWASP Dependency Check Configuration
tasks.named("dependencyCheckAnalyze") {
    dependsOn("assembleDevDebug")
}

tasks.register<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    dependsOn("testDevDebugUnitTest")

    // Configure directories... we just need a dummy implementation so task exists if it's completely missing
}
