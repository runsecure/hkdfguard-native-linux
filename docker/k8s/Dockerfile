# Test image for the Kubernetes Secret-volume tests (docker/k8s/run-tests.sh):
# the hkdfguard CLI, the shared library, cli_unwrap_check, and a policy that
# requires the external-secret provider. Built with default features only
# (external-secret, ephemeral): the tests are about how a real kubelet lays
# out Secret files, not about the hardware providers.
#
# Base images are pinned by digest; the runtime is the same Debian release
# as the builder, so the library and binaries find the glibc they were
# linked against. To take an update, re-resolve both deliberately:
#   docker pull rust:1.99.0 && docker pull debian:13-slim
#   docker image inspect --format '{{index .RepoDigests 0}}' rust:1.99.0 debian:13-slim

FROM rust:1.99.0@sha256:81015672d6939b0265f09adf96d5de125482bb1330106076956b0518e74edc90 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked \
 && ln -sf libhkdfguard.so target/release/libhkdfguard.so.1 \
 && cc -I include examples/cli_unwrap_check.c -L target/release -lhkdfguard -o target/release/cli_unwrap_check

FROM debian:13-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
COPY --from=build /src/target/release/hkdfguard /src/target/release/cli_unwrap_check /usr/local/bin/
COPY --from=build /src/target/release/libhkdfguard.so /usr/local/lib/libhkdfguard.so.1
COPY docker/k8s/pod-test.sh /usr/local/bin/pod-test.sh
# The policy must be root-owned and not writable by anyone else, and so must
# /etc/hkdfguard. A Windows checkout may hand the script CRLF line endings.
RUN ldconfig \
 && sed -i 's/\r$//' /usr/local/bin/pod-test.sh \
 && chmod 0755 /usr/local/bin/pod-test.sh /usr/local/bin/hkdfguard /usr/local/bin/cli_unwrap_check \
 && install -d -m 0755 /etc/hkdfguard \
 && printf '[selection]\nmode = "require"\nprovider = "external-secret"\n' > /etc/hkdfguard/policy.toml \
 && chmod 0644 /etc/hkdfguard/policy.toml
ENTRYPOINT ["/usr/local/bin/pod-test.sh"]
