"""Reads a unified diff (-U0) on stdin and the lcov file scripts/coverage.sh
writes; prints every added line that lcov records as executable with a zero
count, and a summary. Exits 1 if there is any that the exemption file
doesn't list. Used by scripts/coverage.sh.

Takes no arguments: the repository is the one this script is in, and the
two files it reads are where coverage.sh puts them. Nothing on the command
line names a file to open."""
import os
import re
import sys

root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
lcov_path = os.path.join(root, "target", "coverage", "lcov.info")
exempt_path = os.path.join(root, "scripts", "coverage-exempt.txt")
if len(sys.argv) > 1:
    sys.exit("usage: git diff -U0 BASE -- src | coverage_diff.py   (run by scripts/coverage.sh)")


def inside_root(path):
    """`path`, a name from the diff on stdin, taken from the repository
    root with symlinks and `..` resolved -- or None if that leaves the
    repository, where no source file this script reports on can be."""
    resolved = os.path.realpath(os.path.join(root, path))
    if os.path.commonpath([root, resolved]) != root:
        return None
    return resolved


# Exemptions: `path<TAB>source line, stripped<TAB>why`, '#' comments. Lines
# a test runs but whose process can't record a profile.
exempt = {}
if os.path.exists(exempt_path):
    with open(exempt_path) as f:
        for raw in f:
            if raw.strip() and not raw.startswith("#"):
                path, text, why = raw.rstrip("\n").split("\t", 2)
                exempt[(path, text)] = why

# lcov: per source file, line -> max hit count (a line can appear once per
# object; it is covered if any object ran it).
hits = {}
cur = None
with open(lcov_path) as f:
    for line in f:
        if line.startswith("SF:"):
            cur = os.path.relpath(line[3:].strip(), root)
            hits.setdefault(cur, {})
        elif line.startswith("DA:") and cur is not None:
            n, c = line[3:].split(",")[:2]
            n, c = int(n), int(c)
            hits[cur][n] = max(hits[cur].get(n, 0), c)

added = {}
path = None
for line in sys.stdin:
    if line.startswith("+++ "):
        p = line[4:].strip()
        path = p[2:] if p.startswith("b/") else None
    elif line.startswith("@@") and path:
        m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
        start, count = int(m.group(1)), int(m.group(2) or "1")
        added.setdefault(path, set()).update(range(start, start + count))

total = covered = 0
missed = []
exempted = []
for path in sorted(added):
    file_hits = hits.get(path, {})
    src_path = inside_root(path)
    if src_path is None:
        continue  # a diff naming a file outside the repository: not ours to read
    try:
        with open(src_path) as f:
            src = f.read().splitlines()
    except OSError:
        continue
    for n in sorted(added[path]):
        if n not in file_hits:
            continue  # not executable (comment, declaration, cfg'd out)
        total += 1
        text = src[n - 1].strip()
        if file_hits[n] > 0:
            covered += 1
        elif (path, text) in exempt:
            exempted.append(f"  {path}:{n}: {text}\n      ({exempt[(path, text)]})")
        else:
            missed.append(f"  {path}:{n}: {text}")

print("\n".join(missed) if missed else "  (none)")
if exempted:
    print("\nExempted (run by a test, but in a process that can't record coverage):")
    print("\n".join(exempted))
measured = total - len(exempted)
pct = 100.0 * covered / measured if measured else 100.0
print(f"\nadded executable lines: {covered}/{measured} covered ({pct:.2f}%), {len(exempted)} exempted")
sys.exit(1 if missed else 0)
