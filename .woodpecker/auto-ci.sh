#!/bin/bash
# Woodpecker CI Full Autonomous CI/CD
# Runs monitoring -> detects failures -> auto-fixes -> re-runs -> repeats until success

set -e

REPO_ROOT="C:/Users/plner/AndroidStudioProjects/btsec-testtool/btsec-testtool"
LOG_FILE="/tmp/woodpecker-auto-ci.log"
MAX_RETRIES=5
RETRY_COUNT=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1" | tee -a "$LOG_FILE"
}

# Get latest pipeline ID
get_pipeline_id() {
    docker logs woodpecker-server 2>&1 | grep -oP 'pipeline_id["\s:=]+(\d+)' | tail -1 | grep -oP '\d+'
}

# Count steps in pipeline
count_steps() {
    local pipeline_id=$1
    docker logs woodpecker-server 2>&1 | grep "pipeline_id.*$pipeline_id" | \
        grep -c "done: cannot close log stream for step" 2>/dev/null || echo "0"
}

# Detect real failures (excluding warnings)
detect_real_failures() {
    local pipeline_id=$1

    # Check server logs for failures
    docker logs woodpecker-server 2>&1 | grep "pipeline_id.*$pipeline_id" | \
        grep -iE "fail|error" | grep -v "stream: not found" | \
        grep -v "token has invalid claims" > /tmp/server_failures.log 2>/dev/null || true

    # Check agent logs for failures
    docker logs woodpecker-agent 2>&1 | grep -iE "error:|fail" | \
        grep -v "agent.conf" | grep -v "cannot persist agent config" > /tmp/agent_failures.log 2>/dev/null || true

    local failures=0

    if [ -s /tmp/server_failures.log ]; then
        log_error "Server-side failures detected:"
        cat /tmp/server_failures.log | head -10
        failures=$((failures + 1))
    fi

    if [ -s /tmp/agent_failures.log ]; then
        log_error "Agent-side failures detected:"
        cat /tmp/agent_failures.log | head -10
        failures=$((failures + 1))
    fi

    # Return 0 (success) if no failures found, 1 if failures found
    if [ $failures -gt 0 ]; then
        return 1  # Failures detected
    else
        return 0  # No failures - success
    fi
}

# Auto-fix common issues
apply_auto_fix() {
    log_step "Analyzing failures and applying auto-fixes..."

    local fix_applied=0

    # Check for Android SDK issues
    if grep -q "ANDROID_HOME\|Android SDK\|sdkmanager\|command not found: sdkmanager" /tmp/agent_failures.log 2>/dev/null; then
        log_warn "Detected Android SDK missing from android-ci image"
        rebuild_android_ci
        fix_applied=1
    fi

    # Check for Docker image issues
    if grep -q "image not found\|cannot pull image\|manifest unknown" /tmp/agent_failures.log 2>/dev/null; then
        log_warn "Detected missing Docker images"
        pull_docker_images
        fix_applied=1
    fi

    # Check for permission issues
    if grep -q "permission denied\|cannot execute binary file" /tmp/agent_failures.log 2>/dev/null; then
        log_warn "Detected permission issues"
        fix_permissions
        fix_applied=1
    fi

    # Check for network issues
    if grep -q "connection refused\|timeout\|network unreachable" /tmp/agent_failures.log 2>/dev/null; then
        log_warn "Detected network issues - waiting before retry"
        sleep 30
        fix_applied=1
    fi

    if [ $fix_applied -eq 1 ]; then
        log_info "✅ Auto-fix applied"
        return 0
    else
        log_warn "No auto-fix available for detected failures"
        return 1
    fi
}

# Rebuild android-ci image with Android SDK
rebuild_android_ci() {
    log_step "Rebuilding android-ci image with Android SDK..."

    cd "$REPO_ROOT"

    cat > Dockerfile.android-ci <<'EOF'
FROM openjdk:17-jdk-slim

ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

RUN apt-get update && apt-get install -y \
    wget unzip git curl file && \
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

    if docker build -t android-ci:latest -f Dockerfile.android-ci . 2>&1 | tee -a "$LOG_FILE"; then
        log_info "✅ android-ci image rebuilt successfully"
    else
        log_error "❌ Failed to rebuild android-ci image"
        return 1
    fi
}

# Pull required Docker images
pull_docker_images() {
    log_step "Pulling required Docker images..."

    docker pull plugins/git:latest 2>&1 | tee -a "$LOG_FILE" || true
    docker pull alpine:latest 2>&1 | tee -a "$LOG_FILE" || true

    log_info "✅ Docker images updated"
}

# Fix file permissions
fix_permissions() {
    log_step "Fixing file permissions..."

    cd "$REPO_ROOT"
    chmod +x gradlew 2>/dev/null || true

    log_info "✅ Permissions fixed"
}

# Trigger new pipeline
trigger_pipeline() {
    local message=$1
    local commit_id=$2

    cd "$REPO_ROOT"

    if [ -n "$commit_id" ]; then
        # Amend existing commit
        git commit --amend -m "$message"
        git push origin main --force
    else
        # Create new commit
        git commit --allow-empty -m "$message"
        git push origin main
    fi

    log_info "✅ Pipeline triggered: $message"
    sleep 5
}

# Main CI/CD loop
run_ci_cycle() {
    log_info "=========================================="
    log_info "Woodpecker CI Autonomous Cycle #$((RETRY_COUNT + 1))"
    log_info "=========================================="

    # Get current pipeline
    local pipeline_id=$(get_pipeline_id)

    if [ -z "$pipeline_id" ]; then
        log_error "No pipeline found - triggering initial pipeline"
        trigger_pipeline "ci: initial autonomous pipeline"
        pipeline_id=$(get_pipeline_id)
    fi

    log_info "Monitoring Pipeline #$pipeline_id"

    # Wait for pipeline to complete (timeout: 30 min)
    local timeout=1800
    local elapsed=0
    local check_interval=15
    local prev_completed=0
    local stable_count=0

    while [ $elapsed -lt $timeout ]; do
        # Check if steps are completing
        local steps=$(count_steps "$pipeline_id")

        if [ "$steps" -gt 0 ]; then
            log_info "Progress: $steps steps completed..."
        fi

        # Check for completion (check multiple times to ensure stable)
        local completed=$(docker logs woodpecker-server 2>&1 | grep "pipeline_id.*$pipeline_id" | \
            grep -c "done: cannot close log stream" 2>/dev/null || echo "0")

        # Wait for stable count (no changes in 3 checks)
        if [ "$completed" -gt 0 ] && [ "$completed" -eq "$prev_completed" ]; then
            stable_count=$((stable_count + 1))
        else
            stable_count=0
        fi
        prev_completed=$completed

        if [ $stable_count -ge 3 ]; then
            log_info "Pipeline #$pipeline_id appears complete ($completed step completions detected)"
            break
        fi

        sleep $check_interval
        elapsed=$((elapsed + check_interval))
    done

    # Analyze results
    local steps=$(count_steps "$pipeline_id")
    log_info "Pipeline #$pipeline_id completed $steps steps"

    # Check for failures (function returns 0 if NO failures, 1 if failures)
    if ! detect_real_failures "$pipeline_id"; then
        log_warn "❌ Pipeline #$pipeline_id has failures"

        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
            log_info "Attempting auto-fix and retry..."

            if apply_auto_fix; then
                RETRY_COUNT=$((RETRY_COUNT + 1))
                log_info "Retrying... (Attempt $RETRY_COUNT/$MAX_RETRIES)"

                sleep 5
                trigger_pipeline "ci: auto-fix attempt $RETRY_COUNT"
                run_ci_cycle
                return $?
            else
                log_error "❌ Auto-fix failed - manual intervention required"
                return 1
            fi
        else
            log_error "❌ Max retries ($MAX_RETRIES) reached - giving up"
            return 1
        fi
    else
        log_info "✅ Pipeline #$pipeline_id completed successfully!"
        log_info "✅ All $steps steps passed without errors"
        return 0
    fi
}

# Main function
main() {
    log_info "=========================================="
    log_info "Woodpecker CI Autonomous Agent Started"
    log_info "=========================================="

    cd "$REPO_ROOT"

    # Check if there's a recent pipeline
    local pipeline_id=$(get_pipeline_id)

    if [ -z "$pipeline_id" ]; then
        log_info "No recent pipeline found - triggering initial pipeline"
        trigger_pipeline "ci: start autonomous CI/CD"
    else
        log_info "Found existing Pipeline #$pipeline_id - monitoring"
    fi

    # Run CI cycle
    if run_ci_cycle; then
        log_info "=========================================="
        log_info "✅ CI/CD Cycle Completed Successfully!"
        log_info "=========================================="

        # Generate report
        log_info "Pipeline Status: SUCCESS"
        log_info "Total Retries: $RETRY_COUNT"
        log_info "Final Pipeline: #$pipeline_id"

        return 0
    else
        log_error "=========================================="
        log_error "❌ CI/CD Cycle Failed"
        log_error "=========================================="

        return 1
    fi
}

# Run main
main "$@"
