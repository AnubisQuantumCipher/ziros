#!/usr/bin/env bash
set -euo pipefail
# Verification is integrated into the main run.
# This script runs the app which builds, proves, and verifies in one step.
exec "$(dirname "$0")/run.sh" "$@"
