#!/usr/bin/env python3
"""Turns one fuzzing finding into a SARIF file for GitHub code scanning,
which is where .github/workflows/fuzz.yml sends findings: alerts on the
Security tab are shown only to people with write access, unlike a run's
log, summary and artifacts on a public repository.

    finding_sarif.py <target> <log> <artifact dir> <commit> <out.sarif>

The alert carries everything needed to reproduce the finding -- nothing
else keeps it: what the sanitizer or the harness said, the input itself
(base64, with the command that turns it back into a file), and the end of
the fuzzer's log. Prints the upload category on stdout: one per distinct
finding, so that a later finding never replaces an earlier alert and the
same finding on another night updates its own.
"""
import base64
import hashlib
import json
import os
import re
import sys

# Lines that say what went wrong: the harness's panic hook (common.rs), a
# sanitizer's verdict, libFuzzer's own.
REASON = re.compile(r"^(PANIC \(aborting|SUMMARY: |==\d+== ?ERROR: |.*ERROR: libFuzzer: )")
LOG_TAIL_LINES = 60
# A finding's input is at most libFuzzer's -max_len (4096 bytes by default).
MAX_INPUT_BYTES = 64 * 1024


def reason_of(lines):
    """The first line that names the failure, with the one after a panic
    (its message), or a stand-in."""
    for i, line in enumerate(lines):
        if REASON.match(line):
            if line.startswith("PANIC") and i + 1 < len(lines):
                return f"{line.strip()} {lines[i + 1].strip()}"
            return line.strip()
    return "the fuzzer stopped without a sanitizer report or a panic (a timeout, an out-of-memory kill or a signal)"


def stable(reason):
    """`reason` without what changes from run to run: addresses, process
    and thread ids, build ids, paths up to the repository."""
    reason = re.sub(r"0x[0-9a-fA-F]+", "0x?", reason)
    reason = re.sub(r"==\d+==", "", reason)
    reason = re.sub(r"\(BuildId: [0-9a-f]+\)", "", reason)
    reason = re.sub(r"\S*/(fuzz/|src/)", r"\1", reason)
    reason = re.sub(r"\b[T]?\d{3,}\b", "N", reason)
    return " ".join(reason.split())


def main():
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    target, log_path, artifact_dir, commit, out_path = sys.argv[1:]
    with open(log_path, errors="replace") as f:
        lines = f.read().splitlines()
    reason = reason_of(lines)
    fingerprint = hashlib.sha256(f"{target}\n{stable(reason)}".encode()).hexdigest()

    inputs = []
    if os.path.isdir(artifact_dir):
        for name in sorted(os.listdir(artifact_dir)):
            path = os.path.join(artifact_dir, name)
            if os.path.isfile(path) and os.path.getsize(path) <= MAX_INPUT_BYTES:
                with open(path, "rb") as f:
                    inputs.append((name, base64.b64encode(f.read()).decode()))

    replay = []
    for name, encoded in inputs:
        replay.append(
            f"Input `{name}`:\n\n```sh\n"
            f"mkdir -p fuzz/artifacts/{target}\n"
            f"echo '{encoded}' | base64 -d > fuzz/artifacts/{target}/{name}\n"
            f"cargo +nightly fuzz run {target} fuzz/artifacts/{target}/{name}\n```\n"
        )
    if not inputs:
        replay.append("The fuzzer saved no input for this finding; the log below is all there is.\n")
    tail = "\n".join(lines[-LOG_TAIL_LINES:]).replace("```", "'''")
    details = (
        f"Fuzz target `{target}` failed at commit `{commit}`.\n\n**{reason}**\n\n"
        "To reproduce (see fuzz/README.md for `HKDFGUARD_FUZZ_DIR` and `RUSTFLAGS`):\n\n"
        + "\n".join(replay)
        + f"\nThe end of the fuzzer's log:\n\n```\n{tail}\n```\n\n"
        "This alert is the only copy: the run's log, summary and artifacts carry none of it. "
        "A fix is checked by replaying the input above; the alert is then dismissed by hand "
        "(no later run closes it), and the input belongs in fuzz/make_seeds.py."
    )
    # The message is plain text, and what the alert list shows: the reason,
    # then the input once more in case the help text is not shown in full.
    message = f"Fuzzing {target}: {reason}"
    for name, encoded in inputs:
        message += f"\nInput {name} (base64): {encoded}"

    rule_id = f"fuzz/{target}"
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hkdfguard-fuzz",
                        "informationUri": "https://github.com/rust-fuzz/cargo-fuzz",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": "FuzzFinding",
                                "shortDescription": {"text": f"Fuzzing finding in {target}"},
                                "fullDescription": {
                                    "text": f"A libFuzzer run of fuzz/fuzz_targets/{target}.rs crashed, tripped "
                                    "AddressSanitizer, timed out, or broke one of the harness's assertions "
                                    "about the C ABI's contract."
                                },
                                "help": {"text": details, "markdown": details},
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": ["security", "fuzzing"], "security-severity": "8.0"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "ruleIndex": 0,
                        "level": "error",
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f"fuzz/fuzz_targets/{target}.rs"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        "partialFingerprints": {"fuzzFinding/v1": fingerprint},
                    }
                ],
            }
        ],
    }
    with open(out_path, "w") as f:
        json.dump(sarif, f, indent=1)
    print(f"fuzz-{target}-{fingerprint[:16]}")


if __name__ == "__main__":
    main()
