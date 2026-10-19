#!/usr/bin/env bash
# Builds the sles-15.7 test image and runs the SoftHSM2 + Ephemeral
# suite in it, streaming its output. A shortcut for
#   docker/run-distro-tests.sh sles-15.7
# which holds the pinned base image and honors the same environment
# (PLATFORM, KEEP_IMAGES, LOG_DIR). See docker/README.md.
#
# Usage: docker/distros/test-sles-15.7.sh
exec "$(dirname "$0")/../run-distro-tests.sh" sles-15.7
