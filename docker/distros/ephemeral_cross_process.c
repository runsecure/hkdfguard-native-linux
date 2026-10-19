/*
 * Proves the Ephemeral provider's defining property through the C ABI:
 * its KEK lives only in the process that created it. A payload wrapped by
 * one process must be unrecoverable by the next, exactly as after a
 * service restart (src/provider/ephemeral.rs).
 *
 * Run under a policy that requires the ephemeral provider:
 *   ephemeral_cross_process wrap <file>    create the KEK, wrap a DEK,
 *                                          unwrap it in-process, write it
 *   ephemeral_cross_process unwrap <file>  in a new process: the provider
 *                                          answers, but holds no KEK, so
 *                                          the payload must not unwrap
 *
 * Exits 0 only when the expected behavior is observed.
 */

#include <stdio.h>
#include <string.h>
#include "hkdfguard.h"

static const char* SERVICE = "com.hkdfguard.distrotest.ephemeral";

static int do_wrap(const char* path) {
    uint8_t dek[HKDFGUARD_DEK_LEN];
    for (int i = 0; i < HKDFGUARD_DEK_LEN; i++) {
        dek[i] = (uint8_t)(0xA5 ^ i);
    }

    int rc = hkdfguard_create_kek(SERVICE);
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "create_kek failed: %d\n", rc);
        return 1;
    }

    uint8_t wrapped[HKDFGUARD_WRAPPED_MAX_LEN];
    int wrapped_len = sizeof(wrapped);
    rc = hkdfguard_wrap_dek(SERVICE, dek, HKDFGUARD_DEK_LEN, wrapped, &wrapped_len);
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "wrap failed: %d\n", rc);
        return 1;
    }

    /* Same process: the KEK is still in memory, so this must work. */
    uint8_t recovered[HKDFGUARD_DEK_LEN];
    int recovered_len = sizeof(recovered);
    rc = hkdfguard_unwrap_dek(SERVICE, wrapped, wrapped_len, recovered, &recovered_len);
    if (rc != HKDFGUARD_OK || recovered_len != HKDFGUARD_DEK_LEN
            || memcmp(dek, recovered, HKDFGUARD_DEK_LEN) != 0) {
        fprintf(stderr, "in-process unwrap failed: %d\n", rc);
        return 1;
    }

    FILE* f = fopen(path, "wb");
    if (!f || fwrite(wrapped, 1, (size_t)wrapped_len, f) != (size_t)wrapped_len || fclose(f) != 0) {
        fprintf(stderr, "could not write %s\n", path);
        return 1;
    }
    printf("ephemeral: wrapped %d bytes and unwrapped them in the same process\n", wrapped_len);
    return 0;
}

static int do_unwrap(const char* path) {
    uint8_t wrapped[HKDFGUARD_WRAPPED_MAX_LEN];
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "could not open %s\n", path);
        return 1;
    }
    size_t wrapped_len = fread(wrapped, 1, sizeof(wrapped), f);
    fclose(f);

    /* The provider must be reachable (so a failure below is not a
     * configuration problem) yet hold no KEK for the service. */
    int exists = -1;
    int rc = hkdfguard_kek_exists(SERVICE, &exists);
    if (rc != HKDFGUARD_OK || exists != 0) {
        fprintf(stderr, "kek_exists: rc=%d exists=%d (want rc=0, exists=0)\n", rc, exists);
        return 1;
    }

    uint8_t recovered[HKDFGUARD_DEK_LEN];
    int recovered_len = sizeof(recovered);
    rc = hkdfguard_unwrap_dek(SERVICE, wrapped, (int)wrapped_len, recovered, &recovered_len);
    if (rc == HKDFGUARD_OK) {
        fprintf(stderr, "FAIL: a new process unwrapped an ephemeral payload\n");
        return 1;
    }
    /* Any refusal will do: kek_exists above already showed why. (unwrap
     * currently reports a missing KEK as HKDFGUARD_ERR_PROVIDER_ERROR,
     * where wrap reports HKDFGUARD_ERR_KEK_NOT_FOUND.) */
    printf("ephemeral: a new process holds no KEK and refused the payload (rc=%d)\n", rc);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 3 && strcmp(argv[1], "wrap") == 0) {
        return do_wrap(argv[2]);
    }
    if (argc == 3 && strcmp(argv[1], "unwrap") == 0) {
        return do_unwrap(argv[2]);
    }
    fprintf(stderr, "usage: %s wrap|unwrap <file>\n", argv[0]);
    return 2;
}
