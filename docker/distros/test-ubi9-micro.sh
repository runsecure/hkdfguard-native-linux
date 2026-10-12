#!/usr/bin/env bash
# Builds the ubi9-micro test image and runs the SoftHSM2 + Ephemeral
# suite in it, streaming its output. A shortcut for
#   docker/run-distro-tests.sh ubi9-micro
# which holds the pinned base image and honors the same environment
# (PLATFORM, KEEP_IMAGES, LOG_DIR). See docker/README.md.
#
# Usage: docker/distros/test-ubi9-micro.sh
exec "$(dirname "$0")/../run-distro-tests.sh" ubi9-micro
