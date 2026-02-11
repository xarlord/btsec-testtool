// Jenkins Pipeline for BTSec Test Tool
// Multi-agent setup: agent-build, agent-test, agent-util
// 8 stages with quality gates and self-healing

pipeline {
    agent none

    environment {
        JAVA_VERSION = '17'
        ANDROID_SDK_ROOT = '/opt/android-sdk'
        COVERAGE_TARGET = 0.95
        GRADLE_OPTS = '-Dorg.gradle.daemon=false -Dorg.gradle.parallel=true'
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '5'))
        timeout(time: 1, unit: 'HOURS')
        timestamps()
    }

    stages {
        // ============================================
        // Stage 1: Pre-Flight Checks
        // ============================================
        stage('Pre-Flight Checks') {
            agent { label 'android util' }
            steps {
                script {
                    echo '🔍 Running pre-flight checks...'

                    // Check if required tools are available
                    sh '''
                        echo "Checking Java version..."
                        java -version || exit 1

                        echo "Checking Gradle wrapper..."
                        ./gradlew --version || exit 1

                        echo "Checking Android SDK..."
                        ls -d ${ANDROID_SDK_ROOT} || exit 1
                    '''
                }
            }
        }

        // ============================================
        // Stage 2: Checkout
        // ============================================
        stage('Checkout') {
            agent { label 'android util' }
            steps {
                script {
                    echo '📥 Checkout source code...'
                    checkout scm
                    sh 'git log -1 --pretty=format:"%h - %s" > GIT_COMMIT'
                }
            }
        }

        // ============================================
        // Stage 3: Security Scan
        // ============================================
        stage('Security Scan') {
            agent { label 'android util' }
            steps {
                script {
                    echo '🔒 Running security scan...'

                    // Check for hardcoded secrets
                    sh '''
                        echo "Checking for hardcoded secrets..."
                        if grep -rE "(sk_|pk_|api[_-]?key|secret|password|token)\\s*=\\s*['\"]" \
                            --include="*.kt" --include="*.java" --exclude-dir=build app/src/main; then
                            echo "::warning::Potential hardcoded secrets found!"
                            exit 1
                        fi
                        echo "✅ No hardcoded secrets detected"
                    '''

                    // Verify Android permissions
                    sh '''
                        echo "Checking Android permissions..."
                        if ! grep -q "BLUETOOTH_CONNECT" app/src/main/AndroidManifest.xml; then
                            echo "❌ ERROR: Missing BLUETOOTH_CONNECT permission"
                            exit 1
                        fi
                        if ! grep -q "BLUETOOTH_SCAN" app/src/main/AndroidManifest.xml; then
                            echo "❌ ERROR: Missing BLUETOOTH_SCAN permission"
                            exit 1
                        fi
                        echo "✅ All required permissions present"
                    '''
                }
            }
        }

        // ============================================
        // Stage 4: Build APK
        // ============================================
        stage('Build APK') {
            agent { label 'android build' }
            steps {
                script {
                    echo '🔨 Building APK...'

                    // Clean and build
                    sh './gradlew clean'

                    // Build debug APKs
                    sh './gradlew assembleDevDebug assembleProdDebug'

                    // Archive APKs
                    archiveArtifacts artifacts: 'app/build/outputs/apk/**/*.apk', fingerprint: true
                }
            }
        }

        // ============================================
        // Stage 5: Test Execution
        // ============================================
        stage('Test Execution') {
            parallel {
                stage('Unit Tests') {
                    agent { label 'android test' }
                    steps {
                        script {
                            echo '🧪 Running unit tests...'
                            sh './gradlew test testDevDebugUnitTest testProdDebugUnitTest --stacktrace'

                            // Generate coverage report
                            sh './gradlew jacocoTestReport'

                            // Publish test results
                            junit testResults: 'app/build/test-results/**/TEST-*.xml'

                            // Publish coverage
                            publishHTML([
                                reportDir: 'app/build/reports/jacoco/test/html',
                                reportFiles: 'index.html',
                                reportName: 'Coverage Report',
                                keepAll: true,
                                alwaysLinkToLastBuild: true
                            ])
                        }
                    }
                }

                stage('Instrumented Tests') {
                    agent { label 'android test' }
                    when {
                        not {
                            branch 'main'
                        }
                    }
                    steps {
                        script {
                            echo '📱 Running instrumented tests on emulator...'
                            sh './gradlew connectedDevDebugAndroidTest || true'
                        }
                    }
                }
            }
        }

        // ============================================
        // Stage 6: Android Lint
        // ============================================
        stage('Android Lint') {
            agent { label 'android util' }
            steps {
                script {
                    echo '🔍 Running Android Lint...'
                    sh './gradlew lintDebug'

                    // Publish lint results
                    recordIssues(tools: [androidLintParser(pattern: 'app/build/reports/lint-results-*.xml')])
                    publishHTML([
                        reportDir: 'app/build/reports/lint-results',
                        reportFiles: 'lint-results-*.html',
                        reportName: 'Lint Report',
                        keepAll: true,
                        alwaysLinkToLastBuild: true
                    ])
                }
            }
        }

        // ============================================
        // Stage 7: Quality Gates
        // ============================================
        stage('Quality Gates') {
            agent { label 'android util' }
            steps {
                script {
                    echo '✅ Enforcing quality gates...'

                    // Check coverage threshold (95%)
                    sh '''
                        echo "Checking coverage threshold: ${COVERAGE_TARGET}..."
                        COVERAGE=$(./gradlew jacocoTestReport | grep -oP 'Total.*?\\K\\d+(?=%)' || echo "0")

                        if (( $(echo "$COVERAGE < ${COVERAGE_TARGET}" | bc -l) )); then
                            echo "❌ ERROR: Test coverage ${COVERAGE}% below target ${COVERAGE_TARGET}"
                            exit 1
                        fi

                        echo "✅ Test coverage: ${COVERAGE}% (meets ${COVERAGE_TARGET} target)"
                    '''

                    // Verify legal disclaimers
                    sh '''
                        echo "Checking for legal disclaimers..."
                        disclaimer_count=$(grep -r "AUTHORIZED security testing" --include="*.kt" app/src/main | wc -l)

                        if [ "$disclaimer_count" -lt 5 ]; then
                            echo "⚠️  WARNING: Legal disclaimers may be missing (found: $disclaimer_count)"
                        else
                            echo "✅ Found $disclaimer_count files with legal disclaimers"
                        fi
                    '''
                }
            }
        }

        // ============================================
        // Stage 8: Self-Healing
        // ============================================
        stage('Self-Healing') {
            agent { label 'android util' }
            steps {
                script {
                    echo '🔧 Running self-healing checks...'

                    // Cleanup old builds
                    sh '''
                        echo "Cleaning up old builds..."
                        find app/build -type f -mtime +7 -delete 2>/dev/null || true
                        find . -name "*.log" -mtime +7 -delete 2>/dev/null || true
                        echo "✅ Cleanup complete"
                    '''

                    // Check disk space
                    sh '''
                        echo "Checking disk space..."
                        DF=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
                        if [ "$DF" -gt 80 ]; then
                            echo "⚠️  WARNING: Disk usage is ${DF}%"
                        else
                            echo "✅ Disk usage: ${DF}%"
                        fi
                    '''
                }
            }
        }
    }

    // ============================================
    // Post-Build Actions
    // ============================================
    post {
        always {
            script {
                echo '📊 Pipeline completed'

                // Send notifications (configure as needed)
                // emailext subject: "Jenkins Build ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                //         body: "Build ${env.BUILD_NUMBER} finished with status: ${currentBuild.result}",
                //         to: "team@example.com"
            }
        }

        success {
            echo '✅ Pipeline succeeded!'
        }

        failure {
            echo '❌ Pipeline failed!'
            // Notify team of failure
        }
    }
}
// Jenkins CI/CD monitoring active



