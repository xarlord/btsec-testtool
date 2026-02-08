#!/bin/bash
# Woodpecker CI Autonomous Monitor and Auto-Fixer
# Monitors pipeline execution and automatically fixes common issues

set -e

REPO_ROOT="C:/Users/plner/AndroidStudioProjects/btsec-testtool/btsec-testtool"
WOODPECKER_SERVER="http://127.0.0.1:8000"
LOG_FILE="/tmp/woodpecker-monitor.log"
PIPELINE_ID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Get latest pipeline ID from server logs
get_latest_pipeline() {
    docker logs woodpecker-server 2>&1 | grep -oP 'pipeline_id["\s:=]+(\d+)' | tail -1 | grep -oP '\d+'
}

# Monitor pipeline execution
monitor_pipeline() {
    local pipeline_id=$1
    log_info "Monitoring Pipeline #$pipeline_id"

    # Wait for pipeline to start
    sleep 5

    # Monitor execution
    local start_time=$(date +%s)
    local timeout=1800  # 30 minutes max
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        # Check if pipeline completed
        local completed=$(docker logs woodpecker-server 2>&1 | grep "pipeline_id.*$pipeline_id.*done" | wc -l)

        if [ "$completed" -gt 0 ]; then
            log_info "Pipeline #$pipeline_id completed!"
            return 0
        fi

        # Check for running containers
        local running=$(docker ps -a --filter "name=wp-" --format "{{.Names}}" | wc -l)

        if [ "$running" -gt 0 ]; then
            log_info "Pipeline #$pipeline_id: $running step(s) in progress..."
        fi

        sleep 10
        elapsed=$(($(date +%s) - start_time))
    done

    log_warn "Pipeline #$pipeline_id timed out after $timeout seconds"
    return 1
}

# Detect failures from logs
detect_failures() {
    local pipeline_id=$1

    log_info "Analyzing pipeline #$pipeline_id for failures..."

    # Get step completion status
    docker logs woodpecker-server 2>&1 | grep "pipeline_id.*$pipeline_id" > /tmp/pipeline_${pipeline_id}.log

    # Count completed steps
    local steps=$(grep -c "done: cannot close log stream for step" /tmp/pipeline_${pipeline_id}.log 2>/dev/null || echo "0")

    log_info "Pipeline completed $steps steps"

    # Look for error patterns in agent logs (exclude known non-critical warnings)
    docker logs woodpecker-agent 2>&1 | grep -E "error|fail|Error|Fail" | \
        grep -v "agent.conf" | \
        grep -v "cannot persist agent config" > /tmp/agent_errors.log 2>/dev/null || true

    if [ -s /tmp/agent_errors.log ]; then
        log_error "Errors detected in agent logs:"
        cat /tmp/agent_errors.log | head -20
        return 1
    fi

    return 0
}

# Auto-fix common issues
auto_fix() {
    local error_log=$1

    log_info "Attempting auto-fix..."

    # Check for Android SDK issues
    if grep -q "ANDROID_HOME\|Android SDK\|sdkmanager" "$error_log"; then
        log_warn "Detected Android SDK issue - android-ci image needs SDK"
        fix_android_sdk_image
        return $?
    fi

    # Check for Gradle wrapper issues
    if grep -q "gradlew\|Gradle wrapper" "$error_log"; then
        log_warn "Detected Gradle wrapper issue"
        fix_gradle_wrapper
        return $?
    fi

    # Check for Docker image issues
    if grep -q "image not found\|cannot pull image" "$error_log"; then
        log_warn "Detected Docker image issue"
        fix_docker_images
        return $?
    fi

    # Check for permission issues
    if grep -q "permission denied\|cannot access" "$error_log"; then
        log_warn "Detected permission issue"
        fix_permissions
        return $?
    fi

    log_warn "No auto-fix available for this error"
    return 1
}

# Fix: Rebuild android-ci image with Android SDK
fix_android_sdk_image() {
    log_info "Rebuilding android-ci image with Android SDK..."

    cd "$REPO_ROOT"

    cat > Dockerfile.android-ci <<'EOF'
FROM openjdk:17-jdk-slim

ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

RUN apt-get update && apt-get install -y \
    wget unzip git curl && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p ${ANDROID_HOME}/cmdline-tools && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip -O /tmp/cmdline-tools.zip && \
    unzip /tmp/cmdline-tools.zip -d ${ANDROID_HOME}/cmdline-tools && \
    mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest && \
    rm /tmp/cmdline-tools.zip

RUN yes | sdkmanager --licenses && \
    sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"

WORKDIR /woodpecker/src
EOF

    docker build -t android-ci:latest -f Dockerfile.android-ci . 2>&1 | tee -a "$LOG_FILE"

    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        log_info "✅ android-ci image rebuilt successfully"
        return 0
    else
        log_error "❌ Failed to rebuild android-ci image"
        return 1
    fi
}

# Fix: Gradle wrapper permissions
fix_gradle_wrapper() {
    log_info "Fixing Gradle wrapper permissions..."

    cd "$REPO_ROOT"
    chmod +x gradlew

    log_info "✅ Gradle wrapper fixed"
    return 0
}

# Fix: Pull Docker images
fix_docker_images() {
    log_info "Pulling required Docker images..."

    docker pull plugins/git:latest 2>&1 | tee -a "$LOG_FILE"
    docker pull alpine:latest 2>&1 | tee -a "$LOG_FILE"

    log_info "✅ Docker images pulled"
    return 0
}

# Fix: File permissions
fix_permissions() {
    log_info "Fixing file permissions..."

    cd "$REPO_ROOT"
    chmod +x gradlew

    log_info "✅ Permissions fixed"
    return 0
}

# Trigger new pipeline
trigger_pipeline() {
    local message=$1

    cd "$REPO_ROOT"
    git commit --allow-empty -m "$message"
    git push origin main

    log_info "✅ Pipeline triggered with commit: $message"
}

# Main monitoring loop
main() {
    log_info "=== Woodpecker CI Autonomous Monitor Started ==="

    # Get latest pipeline
    PIPELINE_ID=$(get_latest_pipeline)

    if [ -z "$PIPELINE_ID" ]; then
        log_error "No pipeline found to monitor"
        exit 1
    fi

    log_info "Found Pipeline #$PIPELINE_ID"

    # Monitor execution
    if monitor_pipeline "$PIPELINE_ID"; then
        log_info "✅ Pipeline #$PIPELINE_ID monitoring completed"

        # Detect failures
        if detect_failures "$PIPELINE_ID"; then
            log_info "✅ Pipeline #$PIPELINE_ID completed successfully!"
        else
            log_error "❌ Pipeline #$PIPELINE_ID has failures"

            # Attempt auto-fix
            if [ -f /tmp/agent_errors.log ]; then
                if auto_fix /tmp/agent_errors.log; then
                    log_info "✅ Auto-fix applied, triggering new pipeline..."

                    # Trigger new pipeline
                    trigger_pipeline "ci: auto-fix applied - retry pipeline"

                    # Monitor new pipeline (recursive)
                    main
                    return $?
                else
                    log_error "❌ Auto-fix failed - manual intervention required"
                    exit 1
                fi
            fi
        fi
    else
        log_error "❌ Pipeline monitoring failed"
        exit 1
    fi

    log_info "=== Monitoring Complete ==="
}

# Run main function
main "$@"
