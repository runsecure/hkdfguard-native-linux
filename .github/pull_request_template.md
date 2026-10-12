## What and why

<!-- What does this change, and why? -->

## Containerized tests

See [CONTRIBUTING.md](../CONTRIBUTING.md). CI runs the full matrix on
Ubuntu, but the distribution fleet runs only on developer machines, so
please run it before requesting review.

- [ ] `docker/run-tests.sh` (full matrix) passes
- [ ] `docker/run-distro-tests.sh` (every distribution) passes
- [ ] Architecture tested: <!-- arm64 / amd64 / both -->

<!-- If a distribution was skipped or failed, list it and say why. -->
