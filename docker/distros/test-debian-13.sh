#!/usr/bin/env bash
# Builds the debian-13 test image and runs the SoftHSM2 + Ephemeral
# suite in it, streaming its output. A shortcut for
#   docker/run-distro-tests.sh debian-13
# which holds the pinned base image and honors the same environment
# (PLATFORM, KEEP_IMAGES, LOG_DIR). See docker/README.md.
#
# Usage: docker/distros/test-debian-13.sh
exec "$(dirname "$0")/../run-distro-tests.sh" debian-13
