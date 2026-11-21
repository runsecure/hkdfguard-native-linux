#!/usr/bin/env python3
"""Writes fuzz/seeds/<target>/: hand-picked inputs for the C ABI targets,
which fuzz/replay-seeds.sh replays and a fuzzing run can start from.

They are the memory attacks a caller of a C library tries first -- a
capacity one byte short, zero, negative; NULL where a pointer belongs; a
payload cut off inside its header, or with each header byte (the length
fields among them) set to its extremes; a string that ends early, late or
never -- written down so that no run depends on the fuzzer rediscovering
them. Payloads can't be stored (the KEK is made per process), so a seed
names "the genuine payload" and the edits to make to it, as the targets'
inputs do.

A seed is the `arbitrary` encoding of its target's `Input` (arbitrary 1.5,
as fuzz/Cargo.lock pins it), built by the helpers below. When an `Input`
changes shape, change its builder here and rerun:

    python3 fuzz/make_seeds.py            # rewrite fuzz/seeds/ (ignored by git)

`cargo +nightly fuzz fmt <target> fuzz/seeds/<target>/<seed>` prints what a
seed decodes to.
"""
import os
import shutil
import struct
import sys

# ---- the `arbitrary` encoding ----


def variant(index, count):
    """An enum's variant: a u32 scaled onto the variant count."""
    assert 0 <= index < count
    x = -(-(index << 32) // count)  # the smallest u32 that selects `index`
    assert (x * count) >> 32 == index
    return struct.pack("<I", x)


def boolean(b):
    return b"\x01" if b else b"\x00"


def i16(n):
    return struct.pack("<h", n)


def u16(n):
    return struct.pack("<H", n)


def vec(items):
    """A Vec: each element behind a 'one more' byte, then a stop byte."""
    return b"".join(b"\x01" + item for item in items) + b"\x00"


def blob(data):
    """A Vec<u8>."""
    return vec(bytes([b]) for b in data)


def option(item):
    return b"\x00" if item is None else b"\x01" + item


# ---- the types fuzz_targets/common.rs shares ----

SERVICE = b"com.hkdfguard.fuzz"
SECRET_NAME = b"vault.password"


def service(kind, raw=b""):
    kinds = ["fuzz", "upper", "other", "raw", "null"]
    return variant(kinds.index(kind), 5) + (blob(raw) if kind == "raw" else b"")


def secret_name(kind, raw=b""):
    kinds = ["genuine", "other", "upper", "raw", "unterminated", "null"]
    return variant(kinds.index(kind), 6) + (blob(raw) if kind == "raw" else b"")


def call(cap, out_null=False, out_len_null=False):
    return i16(cap) + boolean(out_null) + boolean(out_len_null)


def patches(ops):
    return vec(u16(offset) + bytes([xor]) for offset, xor in ops)


# Output buffers: (name, capacity, out NULL, out_len NULL). `exact` is the
# size the call needs; the others are wrong whatever it is.
def calls(exact):
    return [
        (f"cap-exact-{exact}", exact, False, False),
        (f"cap-one-short-{exact - 1}", exact - 1, False, False),
        (f"cap-one-over-{exact + 1}", exact + 1, False, False),
        ("cap-zero", 0, False, False),
        ("cap-one", 1, False, False),
        ("cap-minus-one", -1, False, False),
        ("cap-most-negative", -32768, False, False),
        ("cap-largest", 32767, False, False),
        ("out-null", exact, True, False),
        ("out-len-null", exact, False, True),
        ("both-null", exact, True, True),
        ("out-null-cap-zero", 0, True, False),
    ]


# Strings a caller might pass where a service or a name belongs.
HOSTILE_STRINGS = [
    ("empty", b""),
    ("one-byte", b"a"),
    ("format-string", b"%s%s%s%n%x%p"),
    ("path-traversal", b"../../../../etc/passwd"),
    ("absolute-path", b"/etc/shadow"),
    ("newline", b"com.hkdfguard.fuzz\nsecurity_model = \"developer\""),
    ("carriage-return", b"com.hkdfguard.fuzz\r\n"),
    ("high-bytes", b"\xff\xfe\xfd\xfc"),
    ("overlong-utf8-nul", b"com\xc0\x80fuzz"),
    ("utf8-bom", b"\xef\xbb\xbfcom.hkdfguard.fuzz"),
    ("space-padded", b" com.hkdfguard.fuzz "),
    ("dot", b"."),
    ("dot-dot", b".."),
    ("shell", b"$(id);`id`|id"),
    ("toml-quote", b"a\"]\n[pkcs11.pinned_keys"),
    ("control-bytes", bytes(range(1, 32))),
    ("del-and-escape", b"a\x7f\x1b[2Jb"),
]


def service_strings():
    out = [(n, service("raw", s)) for n, s in HOSTILE_STRINGS]
    out += [
        ("genuine", service("fuzz")),
        ("genuine-other-case", service("upper")),
        ("no-kek", service("other")),
        ("null", service("null")),
        # The first NUL ends it: this is the genuine service, whatever follows.
        ("early-nul-genuine", service("raw", SERVICE + b"\x00.evil")),
        ("early-nul-at-start", service("raw", b"\x00" + SERVICE)),
        ("early-nul-prefix", service("raw", b"com.hkdfguard\x00.fuzz")),
        ("len-127", service("raw", b"a" * 127)),
        ("len-128-longest", service("raw", b"a" * 128)),
        ("len-129-one-over", service("raw", b"a" * 129)),
        ("len-130", service("raw", b"a" * 130)),
        ("len-256", service("raw", b"a" * 256)),
        ("len-1500", service("raw", b"a" * 1500)),
        ("genuine-then-junk", service("raw", SERVICE + b"x")),
    ]
    return out


def name_strings():
    out = [(n, secret_name("raw", s)) for n, s in HOSTILE_STRINGS]
    out += [
        ("genuine", secret_name("genuine")),
        ("other", secret_name("other")),
        ("uppercase", secret_name("upper")),
        ("null", secret_name("null")),
        ("unterminated", secret_name("unterminated")),
        ("early-nul-genuine", secret_name("raw", SECRET_NAME + b"\x00.evil")),
        ("early-nul-at-start", secret_name("raw", b"\x00" + SECRET_NAME)),
        ("len-63", secret_name("raw", b"a" * 63)),
        ("len-64-longest", secret_name("raw", b"a" * 64)),
        ("len-65-one-over", secret_name("raw", b"a" * 65)),
        ("len-66", secret_name("raw", b"a" * 66)),
        ("len-1500", secret_name("raw", b"a" * 1500)),
    ]
    return out


# Edits to a genuine payload: (name, byte flips, truncate to, bytes appended).
def payload_edits():
    edits = []
    # Every byte of the header (version, provider, the key-id and
    # ciphertext lengths, the fingerprint) at its extremes: a length field
    # that says more than the buffer holds is the classic over-read.
    for offset in range(0, 48):
        for label, xor in (("ff", 0xFF), ("80", 0x80), ("01", 0x01)):
            edits.append((f"header-byte-{offset:02}-xor-{label}", [(offset, xor)], None, b""))
    edits.append(("header-all-ff", [(o, 0xFF) for o in range(16)], None, b""))
    for n in (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 24, 31, 32, 33, 40, 47, 48, 49, 63, 64, 65, 80, 96, 100, 110, 120):
        edits.append((f"truncated-to-{n:03}", [], n, b""))
    edits.append(("last-byte-flipped", [(0xFFFF, 0x01)], None, b""))  # offsets wrap round the payload
    for label, extra in (
        ("one-zero", b"\x00"),
        ("one-ff", b"\xff"),
        ("16-bytes", b"\xa5" * 16),
        ("a-second-header", bytes(48)),
        ("1500-bytes", b"\xff" * 1500),
    ):
        edits.append((f"extended-by-{label}", [], None, extra))
    edits.append(("truncated-then-refilled", [], 20, b"\xff" * 200))
    return edits


RAW_PAYLOADS = [
    ("empty", b""),
    ("one-zero", b"\x00"),
    ("one-ff", b"\xff"),
    ("zeros-64", bytes(64)),
    ("zeros-128", bytes(128)),
    ("ff-64", b"\xff" * 64),
    ("ff-128", b"\xff" * 128),
    ("ff-1500", b"\xff" * 1500),
    ("ascending", bytes(range(256))),
    ("lengths-max", b"\x01\x01" + b"\xff\xff\xff\xff" * 4 + bytes(100)),
    ("lengths-signed-min", b"\x01\x01" + b"\x00\x00\x00\x80" * 4 + bytes(100)),
    ("text", b"-----BEGIN HKDFGUARD KEY-----\n"),
]

# ---- the targets ----


def unwrap_dek():
    body_genuine = variant(0, 3)

    def body_raw(b):
        return variant(1, 3) + blob(b)

    def body_patched(ops, truncate, extend):
        return variant(2, 3) + patches(ops) + option(None if truncate is None else u16(truncate)) + blob(extend)

    good = call(32)
    seeds = {}
    for name, cap, out_null, out_len_null in calls(32):
        seeds[f"buffer-{name}"] = service("fuzz") + body_genuine + call(cap, out_null, out_len_null)
        seeds[f"buffer-{name}-corrupt-payload"] = service("fuzz") + body_patched([(40, 1)], None, b"") + call(cap, out_null, out_len_null)
    for name, svc in service_strings():
        seeds[f"service-{name}"] = svc + body_genuine + good
    for name, ops, truncate, extend in payload_edits():
        seeds[f"payload-{name}"] = service("fuzz") + body_patched(ops, truncate, extend) + good
    for name, raw in RAW_PAYLOADS:
        seeds[f"raw-{name}"] = service("fuzz") + body_raw(raw) + good
    seeds["everything-wrong"] = service("null") + body_raw(b"") + call(-1, True, True)
    return seeds


def unwrap_secret():
    body_genuine, body_dek = variant(0, 4), variant(1, 4)

    def body_raw(b):
        return variant(2, 4) + blob(b)

    def body_patched(ops, truncate, extend):
        return variant(3, 4) + patches(ops) + option(None if truncate is None else u16(truncate)) + blob(extend)

    svc, nm, good = service("fuzz"), secret_name("genuine"), call(256)
    seeds = {}
    for name, cap, out_null, out_len_null in calls(256):
        seeds[f"buffer-{name}"] = svc + nm + body_genuine + call(cap, out_null, out_len_null)
    # The secret is shorter than 256 bytes: room for it is still not enough.
    seeds["buffer-cap-the-secrets-own-length"] = svc + nm + body_genuine + call(30)
    for name, s in service_strings():
        seeds[f"service-{name}"] = s + nm + body_genuine + good
    for name, n in name_strings():
        seeds[f"name-{name}"] = svc + n + body_genuine + good
    for name, ops, truncate, extend in payload_edits():
        seeds[f"payload-{name}"] = svc + nm + body_patched(ops, truncate, extend) + good
    for name, raw in RAW_PAYLOADS:
        seeds[f"raw-{name}"] = svc + nm + body_raw(raw) + good
    seeds["a-dek-payload"] = svc + nm + body_dek + good
    seeds["a-dek-payload-cap-32"] = svc + nm + body_dek + call(32)
    seeds["everything-wrong"] = service("null") + secret_name("null") + body_raw(b"") + call(-1, True, True)
    return seeds


def wrap_round_trip():
    def wrap(dek, dek_null=False):
        return variant(0, 6) + blob(dek) + boolean(dek_null)

    generate, fingerprint = variant(1, 6), variant(3, 6)

    def exists(null):
        return variant(2, 6) + boolean(null)

    def model(model_null, may_write_null):
        return variant(4, 6) + boolean(model_null) + boolean(may_write_null)

    def principal(text):
        return variant(5, 6) + blob(text)

    svc, big = service("fuzz"), call(1024)
    dek = bytes(range(0x40, 0x60))
    seeds = {}
    for n in (0, 1, 16, 31, 32, 33, 48, 64, 256, 1500):
        seeds[f"wrap-dek-len-{n:04}"] = svc + wrap(b"\x5a" * n) + big
    seeds["wrap-dek-null"] = svc + wrap(dek, True) + big
    seeds["wrap-dek-null-and-empty"] = svc + wrap(b"", True) + big
    seeds["wrap-dek-all-zero"] = svc + wrap(bytes(32)) + big
    # A wrapped DEK is about 110 bytes: these capacities straddle it.
    for name, cap, out_null, out_len_null in calls(110) + [(f"cap-{c}", c, False, False) for c in (32, 48, 64, 96, 100, 105, 115, 120, 128, 255, 256)]:
        seeds[f"wrap-buffer-{name}"] = svc + wrap(dek) + call(cap, out_null, out_len_null)
        seeds[f"generate-buffer-{name}"] = svc + generate + call(cap, out_null, out_len_null)
    for name, cap, out_null, out_len_null in calls(32):
        seeds[f"fingerprint-buffer-{name}"] = svc + fingerprint + call(cap, out_null, out_len_null)
    for name, s in service_strings():
        seeds[f"wrap-service-{name}"] = s + wrap(dek) + big
        seeds[f"generate-service-{name}"] = s + generate + big
        seeds[f"exists-service-{name}"] = s + exists(False) + big
        seeds[f"fingerprint-service-{name}"] = s + fingerprint + call(32)
    seeds["exists-out-null"] = svc + exists(True) + big
    seeds["exists-everything-null"] = service("null") + exists(True) + big
    for m in (False, True):
        for w in (False, True):
            seeds[f"security-model-null-{int(m)}{int(w)}"] = svc + model(m, w) + big
    for name, text in [
        ("uid-0", b"uid:0"),
        ("gid-0", b"gid:0"),
        ("uid-u32-max", b"uid:4294967295"),
        ("uid-u32-overflow", b"uid:4294967296"),
        ("uid-i32-overflow", b"uid:2147483648"),
        ("uid-huge", b"uid:99999999999"),
        ("uid-negative", b"uid:-1"),
        ("uid-plus", b"uid:+1"),
        ("uid-hex", b"uid:0x0"),
        ("uid-space", b"uid: 0"),
        ("uid-empty", b"uid:"),
        ("uid-early-nul", b"uid:0\x000000"),
        ("uid-len-15-longest", b"uid:00000000000"),
        ("uid-len-16-one-over", b"uid:000000000000"),
        ("uid-len-1500", b"uid:" + b"0" * 1496),
        ("uppercase", b"UID:0"),
        ("no-colon", b"uid0"),
        ("only-colon", b":"),
        ("two-colons", b"uid:0:0"),
        ("empty", b""),
        ("user-name", b"uid:root"),
        ("unicode-digits", "uid:١".encode()),
        ("format-string", b"%s%n"),
    ]:
        seeds[f"principal-{name}"] = svc + principal(text) + big
    return seeds


def wrap_secret_round_trip():
    def inp(svc, nm, secret, secret_null=False, short_len=None, c=None):
        return (
            svc
            + nm
            + blob(secret)
            + boolean(secret_null)
            + option(None if short_len is None else u16(short_len))
            + (c or call(1024))
        )

    svc, nm = service("fuzz"), secret_name("genuine")
    seeds = {}
    for n in (0, 1, 2, 31, 32, 255, 256, 257, 258, 512, 1500):
        seeds[f"secret-len-{n:04}"] = inp(svc, nm, b"s" * n)
    seeds["secret-null"] = inp(svc, nm, b"secret", secret_null=True)
    seeds["secret-null-and-empty"] = inp(svc, nm, b"", secret_null=True)
    seeds["secret-with-nuls"] = inp(svc, nm, b"pass\x00word\x00\x00")
    seeds["secret-all-nul"] = inp(svc, nm, bytes(256))
    seeds["secret-all-ff"] = inp(svc, nm, b"\xff" * 256)
    seeds["secret-length-zero-of-some"] = inp(svc, nm, b"secret", short_len=0)
    seeds["secret-length-one-of-some"] = inp(svc, nm, b"secret", short_len=1)
    seeds["secret-length-256-of-300"] = inp(svc, nm, b"s" * 300, short_len=256)
    seeds["secret-length-257-of-300"] = inp(svc, nm, b"s" * 300, short_len=257)
    # A wrapped secret is one size whatever the secret's: about 350 bytes.
    for name, cap, out_null, out_len_null in calls(350) + [(f"cap-{c}", c, False, False) for c in (32, 256, 257, 300, 340, 345, 355, 360, 384, 512)]:
        seeds[f"buffer-{name}"] = inp(svc, nm, b"secret", c=call(cap, out_null, out_len_null))
        seeds[f"buffer-{name}-longest-secret"] = inp(svc, nm, b"s" * 256, c=call(cap, out_null, out_len_null))
    for name, s in service_strings():
        seeds[f"service-{name}"] = inp(s, nm, b"secret")
    for name, n in name_strings():
        seeds[f"name-{name}"] = inp(svc, n, b"secret")
    seeds["everything-wrong"] = inp(service("null"), secret_name("null"), b"", True, 0, call(-1, True, True))
    return seeds


PATHS = [
    ("empty", b""),
    ("root", b"/"),
    ("dot", b"."),
    ("dot-dot", b".."),
    ("climb", b"../" * 40 + b"etc/passwd"),
    ("slashes", b"/" * 300),
    ("etc-passwd", b"/etc/passwd"),
    ("etc-shadow", b"/etc/shadow"),
    ("dev-null", b"/dev/null"),
    ("dev-zero", b"/dev/zero"),
    ("dev-urandom", b"/dev/urandom"),
    ("dev-full", b"/dev/full"),
    ("dev-tty", b"/dev/tty"),
    ("dev-stdin", b"/dev/stdin"),
    ("proc-self-mem", b"/proc/self/mem"),
    ("proc-self-maps", b"/proc/self/maps"),
    ("proc-self-environ", b"/proc/self/environ"),
    ("proc-self-exe", b"/proc/self/exe"),
    ("proc-self-fd-0", b"/proc/self/fd/0"),
    ("proc-kcore", b"/proc/kcore"),
    ("sys-file", b"/sys/kernel/mm/transparent_hugepage/enabled"),
    ("tmp", b"/tmp"),
    ("tmp-file", b"/tmp/hkdfguard.key"),
    ("a-directory", b"/etc"),
    ("trailing-slash", b"/etc/passwd/"),
    ("relative", b"key.bin"),
    ("early-nul", b"/etc/passwd\x00.key"),
    ("early-nul-at-start", b"\x00/etc/passwd"),
    ("high-bytes", b"/\xff\xfe/\xfd"),
    ("newline", b"/etc/hkdfguard/key\n.bin"),
    ("component-255", b"/" + b"a" * 255),
    ("component-256", b"/" + b"a" * 256),
    ("len-1500", b"/" + b"a/" * 749 + b"a"),
    ("len-1500-one-component", b"/" + b"a" * 1499),
    ("uri", b"file:///etc/passwd"),
    ("format-string", b"/%s%n%x"),
]


def open_file():
    modes = ["0600", "0400", "0640", "0644", "0700", "0660", "0606", "0666"]

    def content(data, mode, genuine_prefix):
        return variant(0, 2) + blob(data) + variant(modes.index(mode), 8) + boolean(genuine_prefix)

    def path(p):
        return variant(1, 2) + blob(p)

    big = call(1024)
    seeds = {}
    for mode in modes:
        seeds[f"genuine-mode-{mode}"] = content(b"", mode, True) + big
    # A DEK key file is about 110 bytes; below 48 the file is never opened.
    for name, cap, out_null, out_len_null in calls(110) + [(f"cap-{c}", c, False, False) for c in (16, 47, 48, 49, 64, 96, 100, 105, 115, 120, 128, 256)]:
        seeds[f"buffer-{name}"] = content(b"", "0600", True) + call(cap, out_null, out_len_null)
        seeds[f"buffer-{name}-not-a-key-file"] = content(b"\xff" * 200, "0600", False) + call(cap, out_null, out_len_null)
    for label, extra in (("one-zero", b"\x00"), ("one-ff", b"\xff"), ("a-newline", b"\n"), ("1500-bytes", b"\xff" * 1500)):
        seeds[f"genuine-then-{label}"] = content(extra, "0600", True) + big
        seeds[f"genuine-then-{label}-small-buffer"] = content(extra, "0600", True) + call(64)
    for name, raw in RAW_PAYLOADS:
        seeds[f"content-{name}"] = content(raw, "0600", False) + big
        seeds[f"content-{name}-small-buffer"] = content(raw, "0600", False) + call(64)
    for name, p in PATHS:
        seeds[f"path-{name}"] = path(p) + big
    seeds["path-empty-everything-null"] = path(b"") + call(-1, True, True)
    return seeds


def open_secret_file():
    modes = ["0600", "0400", "0640", "0644", "0660", "0606"]
    prefixes = ["none", "secret", "dek"]

    def content(prefix, data, mode):
        if isinstance(prefix, list):
            p = variant(3, 4) + patches(prefix)
        else:
            p = variant(prefixes.index(prefix), 4)
        return variant(0, 2) + p + blob(data) + variant(modes.index(mode), 6)

    def path(p):
        return variant(1, 2) + blob(p)

    big = call(1024)
    seeds = {}
    for mode in modes:
        seeds[f"genuine-mode-{mode}"] = content("secret", b"", mode) + big
    seeds["a-dek-file"] = content("dek", b"", "0600") + big
    for name, cap, out_null, out_len_null in calls(350) + [(f"cap-{c}", c, False, False) for c in (48, 110, 256, 300, 340, 345, 355, 360, 512)]:
        seeds[f"buffer-{name}"] = content("secret", b"", "0600") + call(cap, out_null, out_len_null)
        seeds[f"buffer-{name}-not-a-secret-file"] = content("none", b"\xff" * 400, "0600") + call(cap, out_null, out_len_null)
    for offset in range(0, 48):
        for label, xor in (("ff", 0xFF), ("80", 0x80), ("01", 0x01)):
            seeds[f"header-byte-{offset:02}-xor-{label}"] = content([(offset, xor)], b"", "0600") + big
            seeds[f"header-byte-{offset:02}-xor-{label}-small-buffer"] = content([(offset, xor)], b"", "0600") + call(128)
    for label, extra in (("one-zero", b"\x00"), ("one-ff", b"\xff"), ("1500-bytes", b"\xff" * 1500)):
        seeds[f"genuine-then-{label}"] = content("secret", extra, "0600") + big
    for name, raw in RAW_PAYLOADS:
        seeds[f"content-{name}"] = content("none", raw, "0600") + big
    for name, p in PATHS:
        seeds[f"path-{name}"] = path(p) + big
    return seeds


def string_bounds():
    service_fns = ["create-kek", "exists", "fingerprint", "wrap", "unwrap", "generate", "wrap-secret", "unwrap-secret"]
    args = [(f"service-{fn}", variant(0, 4) + variant(i, 8)) for i, fn in enumerate(service_fns)]
    args += [
        ("name-wrap-secret", variant(1, 4) + boolean(True)),
        ("name-unwrap-secret", variant(1, 4) + boolean(False)),
        ("path-open-file", variant(2, 4) + boolean(False)),
        ("path-open-secret-file", variant(2, 4) + boolean(True)),
        ("principal", variant(3, 4)),
    ]

    def early_nul(head, tail):
        text = variant(0, 2) if head is None else variant(1, 2) + blob(head)
        return variant(3, 4) + text + blob(tail)

    seeds = {}
    for name, arg in args:
        for fill_name, fill in (("a", 0x61), ("ff", 0xFF), ("01", 0x01), ("slash", 0x2F)):
            seeds[f"{name}-unterminated-fill-{fill_name}"] = arg + variant(0, 4) + bytes([fill])
            seeds[f"{name}-one-over-the-limit-fill-{fill_name}"] = arg + variant(2, 4) + bytes([fill])
        seeds[f"{name}-longest"] = arg + variant(1, 4) + b"a"
        seeds[f"{name}-genuine-nul-is-last-byte"] = arg + early_nul(None, b"") + b"a"
        seeds[f"{name}-genuine-then-nul-then-junk"] = arg + early_nul(None, b".evil") + b"a"
        seeds[f"{name}-genuine-then-nul-then-1500-bytes"] = arg + early_nul(None, b"\xff" * 1500) + b"a"
        seeds[f"{name}-genuine-then-nul-then-another-string"] = arg + early_nul(None, b"com.hkdfguard.other\x00") + b"a"
        seeds[f"{name}-empty-then-junk"] = arg + early_nul(b"", b"com.hkdfguard.fuzz") + b"a"
        seeds[f"{name}-one-byte-then-junk"] = arg + early_nul(b"a", b"bc") + b"a"
        for hostile, text in HOSTILE_STRINGS[2:8]:
            seeds[f"{name}-{hostile}-then-nul"] = arg + early_nul(text, b"\xff") + b"a"
    return seeds


def api_threads():
    def op(index, body=b""):
        return variant(index, 11) + body

    create, fingerprint, generate, secret_genuine, wrap_other = op(0), op(2), op(4), op(8), op(10)

    def exists(other):
        return op(1, boolean(other))

    def wrap_unwrap(byte, upper=False):
        return op(3, bytes([byte]) * 32 + boolean(upper))

    def unwrap_genuine(cap):
        return op(5, i16(cap))

    def unwrap_patched(offset, xor):
        return op(6, u16(offset) + bytes([xor]))

    def secret(data):
        return op(7, blob(data))

    def open_file(cap):
        return op(9, i16(cap))

    def threads(*lists):
        return vec(vec(ops) for ops in lists)

    everything = [
        create, exists(False), exists(True), fingerprint, wrap_unwrap(1), wrap_unwrap(2, True), generate, unwrap_genuine(32),
        unwrap_genuine(31), unwrap_patched(40, 1), secret(b"secret"), secret_genuine, open_file(1024), open_file(16), wrap_other,
    ]
    return {
        "every-op-on-four-threads": threads(everything, everything[::-1], everything[5:] + everything[:5], everything[::2]),
        "create-kek-on-four-threads": threads(*[[create] * 12] * 4),
        "create-kek-against-wrap": threads([create] * 12, [wrap_unwrap(3)] * 12, [create, generate] * 6, [wrap_unwrap(4, True)] * 12),
        "distinct-deks-on-four-threads": threads(*[[wrap_unwrap(b)] * 16 for b in (0x11, 0x22, 0x33, 0x44)]),
        "distinct-secrets-on-four-threads": threads(*[[secret(bytes([b]) * n)] * 3 for b, n in ((1, 1), (2, 32), (3, 100), (4, 256))]),
        "unwrap-genuine-against-corrupt": threads([unwrap_genuine(32)] * 16, [unwrap_patched(o, 0xFF) for o in range(16)], [unwrap_genuine(0), unwrap_genuine(-1)] * 8),
        "small-buffers-on-four-threads": threads(*[[unwrap_genuine(c), open_file(c)] * 8 for c in (0, 1, 31, -1)]),
        "open-file-against-wrap": threads([open_file(1024)] * 16, [wrap_unwrap(5)] * 16, [open_file(47), open_file(48)] * 8),
        "fingerprint-and-exists-against-generate": threads([fingerprint, exists(False), exists(True)] * 8, [generate] * 16, [wrap_other] * 16),
        "secrets-against-deks": threads([secret_genuine] * 16, [unwrap_genuine(32)] * 16, [secret(b"")] * 4 + [secret(b"s" * 300)] * 4),
        "two-threads": threads([wrap_unwrap(6)] * 8, [wrap_unwrap(7)] * 8),
    }


TARGETS = {
    "unwrap_dek": unwrap_dek,
    "unwrap_secret": unwrap_secret,
    "wrap_round_trip": wrap_round_trip,
    "wrap_secret_round_trip": wrap_secret_round_trip,
    "open_file": open_file,
    "open_secret_file": open_secret_file,
    "string_bounds": string_bounds,
    "api_threads": api_threads,
}

# libFuzzer's default: a longer input is never run.
MAX_SEED_LEN = 4096
# Below an `Input`'s smallest encoding the harness skips the input unseen;
# trailing zeros decode to nothing, so every seed is padded past it.
MIN_SEED_LEN = 64


def write(root):
    count = 0
    for target, build in TARGETS.items():
        directory = os.path.join(root, target)
        os.makedirs(directory)
        for name, data in build().items():
            assert len(data) <= MAX_SEED_LEN, f"{target}/{name}: {len(data)} bytes, over libFuzzer's default -max_len"
            with open(os.path.join(directory, name), "wb") as f:
                f.write(data.ljust(MIN_SEED_LEN, b"\x00"))
            count += 1
    return count


def main():
    if sys.argv[1:]:
        sys.exit(__doc__)
    seeds = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")
    shutil.rmtree(seeds, ignore_errors=True)
    print(f"fuzz/seeds: wrote {write(seeds)} seeds")


if __name__ == "__main__":
    main()
