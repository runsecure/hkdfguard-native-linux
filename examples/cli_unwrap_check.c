/*
 * Verifies that a wrapped-key file produced by the hkdfguard
 * CLI tool (which links this crate's Rust code statically, as an rlib)
 * unwraps cleanly through libhkdfguard_v1.so loaded
 * dynamically here -- proving the wrapped payload's wire format is truly
 * consumer-independent, not an artifact of both sides sharing one binary.
 *
 * Usage: cli_unwrap_check <wrapped-file> <service> <expected-dek-file>
 *   <wrapped-file>       output of `hkdfguard wrap`
 *   <service>            the exact --service-name the CLI wrapped it under
 *   <expected-dek-file>  the original 32 raw DEK bytes given to the CLI
 *                         (before base64-encoding for --dek-stdin/--dek-file)
 *
 * Build (after `cargo build --release` and
 *   `ln -sf libhkdfguard_v1.so ../target/release/libhkdfguard.so.1`,
 *   the library's SONAME; with the packages installed, use
 *   `pkg-config --cflags --libs hkdfguard` instead):
 *   cc -I../include cli_unwrap_check.c -L../target/release \
 *       -lhkdfguard_v1 -o cli_unwrap_check
 *   LD_LIBRARY_PATH=../target/release ./cli_unwrap_check \
 *       <wrapped-file> <service> <expected-dek-file>
 */

#include <stdio.h>
#include <string.h>
#include "hkdfguard.h"

static long read_file(const char* path, uint8_t* buf, long max_len) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }
    long n = (long)fread(buf, 1, (size_t)max_len, f);
    fclose(f);
    return n;
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <wrapped-file> <service> <expected-dek-file>\n", argv[0]);
        return 2;
    }
    const char* wrapped_path = argv[1];
    const char* service = argv[2];
    const char* expected_dek_path = argv[3];

    /* Read the key file the way an application should: the library checks
     * it is a complete, well-formed wrapped DEK before handing it over. */
    uint8_t wrapped[HKDFGUARD_WRAPPED_MAX_LEN];
    int wrapped_len = (int)sizeof(wrapped);
    int rc = hkdfguard_open_file(wrapped_path, wrapped, &wrapped_len);
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "hkdfguard_open_file(%s) failed: %d\n", wrapped_path, rc);
        return 1;
    }

    uint8_t expected_dek[HKDFGUARD_DEK_LEN];
    long expected_len = read_file(expected_dek_path, expected_dek, (long)sizeof(expected_dek));
    if (expected_len != HKDFGUARD_DEK_LEN) {
        fprintf(stderr, "expected DEK file must be exactly %d bytes, got %ld\n", HKDFGUARD_DEK_LEN, expected_len);
        return 1;
    }

    /* The expected-DEK file is a plaintext key: hkdfguard_open_file must
     * refuse it as one, and leave nothing of it in the buffer. */
    uint8_t probe[HKDFGUARD_WRAPPED_MAX_LEN];
    int probe_len = (int)sizeof(probe);
    rc = hkdfguard_open_file(expected_dek_path, probe, &probe_len);
    if (rc != HKDFGUARD_ERR_FILE_PLAINTEXT_KEY || probe_len != 0) {
        fprintf(stderr, "hkdfguard_open_file on a raw DEK returned %d (len %d), expected %d\n",
                rc, probe_len, HKDFGUARD_ERR_FILE_PLAINTEXT_KEY);
        return 1;
    }

    uint8_t recovered[HKDFGUARD_DEK_LEN];
    int recovered_len = sizeof(recovered);
    rc = hkdfguard_unwrap_dek(service, wrapped, wrapped_len, recovered, &recovered_len);
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "hkdfguard_unwrap_dek failed: %d\n", rc);
        return 1;
    }

    if (recovered_len != HKDFGUARD_DEK_LEN || memcmp(recovered, expected_dek, HKDFGUARD_DEK_LEN) != 0) {
        fprintf(stderr, "unwrapped DEK does not match the original DEK given to the CLI\n");
        return 1;
    }

    printf("CLI-wrapped key unwraps cleanly via libhkdfguard_v1.so (service \"%s\")\n", service);
    return 0;
}
