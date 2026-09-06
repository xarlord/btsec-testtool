// Root build.gradle.kts
plugins {
    id("com.android.application") version "8.2.1" apply false
    id("com.android.library") version "8.2.1" apply false
    id("org.jetbrains.kotlin.android") version "1.9.21" apply false
    id("com.google.dagger.hilt.android") version "2.48.1" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "1.9.21" apply false
    id("com.google.devtools.ksp") version "1.9.21-1.0.16" apply false
    id("org.owasp.dependencycheck") version "9.0.9" apply false
}

// Force Java 17 toolchain for all projects
allprojects {
    plugins.withType<JavaPlugin> {
        extensions.configure<JavaPluginExtension> {
            toolchain {
                languageVersion.set(JavaLanguageVersion.of(17))
            }
        }
    }

    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
        kotlinOptions {
            jvmTarget = "17"
        }
    }
}

tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}

/**
 * Runs the same repository-local ktlint checker used by CI on Unix-like hosts.
 * Security testing must remain authorized.
 */
tasks.register<Exec>("ktlint") {
    group = "verification"
    description = "Runs the repository ktlint style checker."
    commandLine("bash", rootProject.file("scripts/lint-ktlint.sh").absolutePath)
}
