#!/usr/bin/env bash
# Builds the ubi10-micro test image and runs the SoftHSM2 + Ephemeral
# suite in it, streaming its output. A shortcut for
#   docker/run-distro-tests.sh ubi10-micro
# which holds the pinned base image and honors the same environment
# (PLATFORM, KEEP_IMAGES, LOG_DIR). See docker/README.md.
#
# Usage: docker/distros/test-ubi10-micro.sh
exec "$(dirname "$0")/../run-distro-tests.sh" ubi10-micro
