#!/usr/bin/env python3
"""Black-box fuzzer for the `hkdfguard` CLI: runs the real binary, as a
separate process, under randomly generated and mutated command lines,
stdin contents, --dek-file contents and key-file paths, and records every
run that crashes (a signal), panics, reports an internal error, or hangs.
An ordinary refusal (exit 1 or 2 with a message) is the expected outcome
of most runs and is not a finding.

The binary must be built with `--cfg hkdfguard_test_paths` so that it
reads HKDFGUARD_POLICY_FILE; each worker gets its own private directory
with a policy pinning the chain to external-secret and a pre-provisioned
secret per service, as tests/cli_round_trip.rs does.

Usage: cli_blackbox.py <binary> <private dir> <seconds> <workers>
"""
import base64
import json
import multiprocessing
import os
import random
import shutil
import stat
import subprocess
import sys
import time

BIN, ROOT, SECONDS, WORKERS = sys.argv[1], sys.argv[2], float(sys.argv[3]), int(sys.argv[4])
TIMEOUT = 20

SERVICES = ["com.fuzz.alpha", "com.fuzz.beta"]
SERVICE_POOL = SERVICES + [
    "COM.FUZZ.ALPHA", "", ".", "..", "a", "-", "a..b", ".a", "a.", "a b", "a\tb", "a\nb",
    "x" * 128, "x" * 129, "x" * 4096, "com.fuzz.alpha\0", "é.ü", "🔑", "a/b", "../etc",
    "a-b_c.d", "A" * 127 + ".", "com.fuzz.alpha ", " com.fuzz.alpha",
]
FLAGS = [
    "--service-name", "-sn", "--key-file-path", "-kf", "--dek-stdin", "--dek-file", "--force", "-f",
    "--group", "-g", "--fingerprint", "-fp", "--help", "-h", "help", "--", "-", "---", "--Service-Name",
    "--service-name=x", "-sn=x", "--dek-stdin=1",
]
SUBCOMMANDS = ["provision", "wrap", "retire", "Wrap", "unwrap", "", "--help", "help", "-h"]
GROUP_POOL = ["root", "0", "65534", "nogroup", "users", str(os.getgid()), "nosuchgroup", "", "x" * 300, "1" * 20, "-1", "4294967295", "4294967296"]


def dek_b64(dek=None):
    return base64.b64encode(dek or os.urandom(32)).decode()


def fingerprint_pool():
    return ["0" * 64, "f" * 64, "G" * 64, "0" * 63, "0" * 65, "", "0x" + "0" * 62, "ab" * 32, " " * 64]


class Worker:
    def __init__(self, index):
        self.rng = random.Random(index * 7919 + int(time.time()))
        self.dir = os.path.join(ROOT, f"w{index}")
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir, mode=0o700)
        secrets = os.path.join(self.dir, "secrets")
        os.makedirs(secrets, mode=0o700)
        for svc in SERVICES:
            path = os.path.join(secrets, svc)
            with open(path, "wb") as f:
                f.write(b"\x00" + os.urandom(31))  # a P-256 scalar below the group order
            os.chmod(path, 0o600)
        self.policy = os.path.join(self.dir, "policy.toml")
        with open(self.policy, "w") as f:
            f.write(f'security_model = "developer"\n[selection]\nmode = "require"\nprovider = "external-secret"\n'
                    f'[external_secret]\ndir = "{secrets}"\n[startup_behavior]\nsetup_min_delay_ms = 0\n')
        os.chmod(self.policy, 0o644)
        self.keys = os.path.join(self.dir, "keys")
        os.makedirs(self.keys, mode=0o700)
        self.deks = os.path.join(self.dir, "deks")
        os.makedirs(self.deks, mode=0o700)
        # Fixed fixtures: an existing key file, a symlink, a directory, a world-readable DEK file.
        self.existing_key = os.path.join(self.keys, "existing.bin")
        open(self.existing_key, "wb").write(os.urandom(100))
        os.chmod(self.existing_key, 0o600)
        os.symlink("/etc/passwd", os.path.join(self.keys, "link"))
        os.makedirs(os.path.join(self.keys, "subdir"), mode=0o700)
        self.world_dek = os.path.join(self.deks, "world.txt")
        open(self.world_dek, "w").write(dek_b64())
        os.chmod(self.world_dek, 0o644)
        self.env = dict(os.environ, HKDFGUARD_POLICY_FILE=self.policy, RUST_BACKTRACE="1")
        self.findings = os.path.join(ROOT, "findings")
        os.makedirs(self.findings, exist_ok=True)
        self.n = 0

    # --- generators ---------------------------------------------------
    def junk(self):
        r = self.rng
        kind = r.randrange(8)
        if kind == 0:
            return os.urandom(r.randrange(1, 40))  # likely invalid UTF-8
        if kind == 1:
            return ("x" * r.choice([1, 100, 4096, 65536])).encode()
        if kind == 2:
            return r.choice(SERVICE_POOL).encode()
        if kind == 3:
            return r.choice(FLAGS).encode()
        if kind == 4:
            return r.choice(fingerprint_pool()).encode()
        if kind == 5:
            return str(r.choice([0, -1, 2 ** 31, 2 ** 64, 1.5])).encode()
        if kind == 6:
            return "".join(chr(r.randrange(1, 0x110000)) for _ in range(r.randrange(1, 20))).encode("utf-8", "surrogatepass")
        return b""

    def key_path(self):
        r = self.rng
        self.n += 1
        return r.choice([
            os.path.join(self.keys, f"k{self.n}.bin"),
            os.path.join(self.keys, f"k{self.n}.bin"),
            self.existing_key,
            os.path.join(self.keys, "link"),
            os.path.join(self.keys, "subdir"),
            os.path.join(self.keys, "nosuch", "k.bin"),
            os.path.join(self.keys, "x" * r.choice([255, 256, 4096])),
            os.path.join(self.keys, "a\nb.bin"),
            os.path.join(self.keys, "é🔑.bin"),
            self.keys,
            "/tmp/k.bin", "/etc/k.bin", "/dev/null", "/proc/self/mem", "/", "", ".", "..", "k.bin", "./k.bin",
            os.path.join(self.keys, "..", "keys", f"k{self.n}.bin"),
        ])

    def dek_file(self):
        r = self.rng
        kind = r.randrange(8)
        if kind == 0:
            return self.world_dek
        if kind == 1:
            return r.choice(["/dev/null", "/etc/passwd", "/nonexistent", self.deks, "/dev/zero", "/proc/self/status", ""])
        path = os.path.join(self.deks, f"d{self.n}.txt")
        content = self.stdin_content()
        with open(path, "wb") as f:
            f.write(content)
        os.chmod(path, r.choice([0o600, 0o600, 0o400, 0o640, 0o000, 0o644]))
        if kind == 2:
            link = os.path.join(self.deks, f"l{self.n}")
            os.symlink(path, link)
            return link
        return path

    def stdin_content(self):
        r = self.rng
        kind = r.randrange(12)
        d = dek_b64().encode()
        if kind <= 3:
            return d + r.choice([b"", b"\n", b"\r\n", b"\n\n", b" ", b"\t"])
        if kind == 4:
            return b"\xef\xbb\xbf" + d
        if kind == 5:
            return r.choice([b"\xff\xfe", b"\xfe\xff"]) + d.decode().encode("utf-16-le")
        if kind == 6:
            return base64.b64encode(os.urandom(r.choice([0, 1, 31, 33, 48, 64, 100]))) + b"\n"
        if kind == 7:
            return base64.urlsafe_b64encode(os.urandom(32))
        if kind == 8:
            return d.rstrip(b"=")
        if kind == 9:
            return os.urandom(r.choice([1, 44, 64, 65, 100, 100000]))
        if kind == 10:
            return b""
        return bytes(r.randrange(256) for _ in range(r.randrange(1, 70)))

    def structured(self):
        """A mostly valid command line, then mutated."""
        r = self.rng
        sub = r.choice(["wrap", "wrap", "wrap", "provision", "retire"])
        svc = r.choice(SERVICES + SERVICE_POOL[:4]) if r.random() < 0.8 else r.choice(SERVICE_POOL)
        argv = [sub]
        stdin = None
        if sub == "wrap":
            argv += [r.choice(["--key-file-path", "-kf"]), self.key_path()]
            argv += [r.choice(["--service-name", "-sn"]), svc]
            if r.random() < 0.6:
                argv.append("--dek-stdin")
                stdin = self.stdin_content()
            else:
                argv += ["--dek-file", self.dek_file()]
            if r.random() < 0.3:
                argv.append(r.choice(["--force", "-f"]))
            if r.random() < 0.3:
                argv += [r.choice(["--group", "-g"]), r.choice(GROUP_POOL)]
            if r.random() < 0.3:
                argv += [r.choice(["--fingerprint", "-fp"]), r.choice(fingerprint_pool())]
        elif sub == "provision":
            argv += [r.choice(["--service-name", "-sn"]), svc]
        else:
            argv += [r.choice(["--service-name", "-sn"]), svc, "--fingerprint", r.choice(fingerprint_pool())]
        argv = [a.encode("utf-8", "surrogatepass") if isinstance(a, str) else a for a in argv]
        # Mutations.
        for _ in range(r.choice([0, 0, 0, 1, 1, 2, 3])):
            m = r.randrange(5)
            if m == 0 and argv:
                del argv[r.randrange(len(argv))]
            elif m == 1:
                argv.insert(r.randrange(len(argv) + 1), self.junk())
            elif m == 2 and argv:
                i = r.randrange(len(argv))
                argv.insert(r.randrange(len(argv) + 1), argv[i])
            elif m == 3 and len(argv) > 1:
                i, j = r.randrange(len(argv)), r.randrange(len(argv))
                argv[i], argv[j] = argv[j], argv[i]
            elif m == 4 and argv:
                i = r.randrange(len(argv))
                b = bytearray(argv[i])
                if b:
                    b[r.randrange(len(b))] = r.randrange(256)
                argv[i] = bytes(b)
        if stdin is None and r.random() < 0.3:
            stdin = self.stdin_content()
        return argv, stdin

    def soup(self):
        r = self.rng
        n = r.choice([0, 1, 2, 3, 5, 8, 20, 200])
        argv = [r.choice(SUBCOMMANDS).encode()] if r.random() < 0.8 else []
        argv += [self.junk() for _ in range(n)]
        return argv, self.stdin_content() if r.random() < 0.5 else None

    # --- the run ------------------------------------------------------
    def one(self):
        argv, stdin = self.structured() if self.rng.random() < 0.75 else self.soup()
        argv = [a for a in argv if b"\0" not in a]  # argv can't carry NUL
        try:
            p = subprocess.run([BIN] + argv, input=stdin if stdin is not None else b"", env=self.env,
                               capture_output=True, timeout=TIMEOUT, cwd=self.keys)
            rc, out, err = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            rc, out, err = "timeout", e.stdout or b"", e.stderr or b""
        finding = None
        if rc == "timeout":
            finding = "hang"
        elif rc < 0:
            finding = f"signal {-rc}"
        elif b"panicked at" in err or b"RUST_BACKTRACE" in err[-2000:] and b"panic" in err:
            finding = "panic"
        elif b"internal error" in err.lower() or b"INTERNAL_ERROR" in err:
            finding = "internal error"
        elif rc not in (0, 1, 2):
            finding = f"exit {rc}"
        if finding:
            key = finding + ":" + (err.split(b"panicked at")[1][:80].decode("utf-8", "replace") if b"panicked at" in err else "")
            self.record(key, finding, argv, stdin, rc, out, err)
        if len(os.listdir(self.keys)) > 500:
            for name in os.listdir(self.keys):
                if name.startswith("k"):
                    os.remove(os.path.join(self.keys, name))
        if len(os.listdir(self.deks)) > 500:
            for name in os.listdir(self.deks):
                if name.startswith(("d", "l")):
                    os.remove(os.path.join(self.deks, name))
        return rc, finding

    def record(self, key, finding, argv, stdin, rc, out, err):
        name = base64.urlsafe_b64encode(key.encode()).decode()[:60]
        path = os.path.join(self.findings, name + ".json")
        if os.path.exists(path):
            return
        with open(path, "w") as f:
            json.dump({
                "finding": finding, "rc": rc,
                "argv": [base64.b64encode(a).decode() for a in argv],
                "stdin": base64.b64encode(stdin).decode() if stdin is not None else None,
                "stdout": out[-4000:].decode("utf-8", "replace"),
                "stderr": err[-8000:].decode("utf-8", "replace"),
            }, f, indent=1)
        print(f"FINDING [{finding}] saved to {path}", flush=True)


def run_worker(index):
    w = Worker(index)
    deadline = time.time() + SECONDS
    counts, findings = {}, 0
    while time.time() < deadline:
        rc, finding = w.one()
        counts[str(rc)] = counts.get(str(rc), 0) + 1
        findings += bool(finding)
    return counts, findings


if __name__ == "__main__":
    os.makedirs(ROOT, mode=0o700, exist_ok=True)
    with multiprocessing.Pool(WORKERS) as pool:
        results = pool.map(run_worker, range(WORKERS))
    total, findings = {}, 0
    for counts, n in results:
        findings += n
        for k, v in counts.items():
            total[k] = total.get(k, 0) + v
    runs = sum(total.values())
    print(f"\n{runs} runs in {SECONDS:.0f}s x {WORKERS} workers; exit codes: {json.dumps(total, sort_keys=True)}; findings: {findings}")
    sys.exit(1 if findings else 0)
