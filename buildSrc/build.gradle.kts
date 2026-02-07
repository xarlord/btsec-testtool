plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
    google()
}

// Force Java 17 for buildSrc compilation
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
        jvmTarget = "17"
    }
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}
