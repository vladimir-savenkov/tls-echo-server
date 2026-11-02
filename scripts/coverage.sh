#!/usr/bin/env bash
# Measures line coverage of the test suite over src/ and include/.
#
# Usage: scripts/coverage.sh
#
# Builds into build/coverage with ENABLE_COVERAGE=ON, runs ctest, then
# aggregates gcov data and prints per-file and total coverage. A copy of
# the report is saved to build/coverage/coverage-report/coverage.txt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/coverage"
REPORT="$BUILD/coverage-report"

cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON
cmake --build "$BUILD" --parallel "$(nproc)"
ctest --test-dir "$BUILD" --output-on-failure

# Run gcov once per object directory so that coverage for headers
# included from multiple translation units is not overwritten.
# Process .gcno files (not .gcda) so that executables which were never
# run by the tests still count as 0% instead of being omitted.
rm -rf "$REPORT"
mkdir -p "$REPORT/obj"
while IFS= read -r -d '' gcno; do
    obj_dir="$REPORT/obj/$(dirname "${gcno#"$BUILD/"}")"
    mkdir -p "$obj_dir"
    (cd "$obj_dir" && gcov "$gcno" >/dev/null 2>&1 || true)
done < <(find "$BUILD" -name '*.gcno' -print0)

python3 - "$ROOT" "$REPORT/obj" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
obj_root = pathlib.Path(sys.argv[2])
keep_prefixes = (str(root / "src") + "/", str(root / "include") + "/")

# source path -> {line number: total hit count across all objects}
files: dict[str, dict[int, int]] = {}

for gcov_file in obj_root.rglob("*.gcov"):
    lines = gcov_file.read_text(encoding="utf-8", errors="replace").splitlines()
    source = None
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) < 3 or parts[1].strip() != "0":
            continue
        field = parts[2].strip()
        if field.startswith("Source:"):
            source = field[len("Source:"):].strip()
            break
    if source is None:
        continue
    try:
        source = str(pathlib.Path(source).resolve())
    except OSError:
        continue
    if not source.startswith(keep_prefixes):
        continue
    counts = files.setdefault(source, {})
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        hit, lineno = parts[0].strip(), parts[1].strip()
        if not lineno.isdigit():
            continue
        if hit == "-":
            continue  # not executable
        if hit == "=====":
            continue  # unexecutable (e.g. unreachable catch block)
        counts[int(lineno)] = counts.get(int(lineno), 0) + (int(hit) if hit.isdigit() else 0)

def pct(covered: int, total: int) -> str:
    return f"{100.0 * covered / total:.2f}%" if total else "n/a"

def display(path: str) -> str:
    try:
        return str(pathlib.Path(path).relative_to(root))
    except ValueError:
        return path

rows = []
for path, counts in sorted(files.items()):
    total = len(counts)
    covered = sum(1 for n in counts.values() if n > 0)
    rows.append((display(path), total, covered))

grand_total = sum(r[1] for r in rows)
grand_covered = sum(r[2] for r in rows)

text = [f"{'Lines':>7}  {'Covered':>7}  {'Percent':>8}  File"]
markdown = ["# Code coverage", "",
            "| Lines | Covered | Percent | File |",
            "|---:|---:|---:|---|"]
for path, total, covered in rows:
    text.append(f"{total:>7}  {covered:>7}  {pct(covered, total):>8}  {path}")
    markdown.append(f"| {total} | {covered} | {pct(covered, total)} | `{path}` |")
text.append(f"{grand_total:>7}  {grand_covered:>7}  {pct(grand_covered, grand_total):>8}  TOTAL")
markdown.append(f"| {grand_total} | {grand_covered} | "
                f"**{pct(grand_covered, grand_total)}** | TOTAL |")

text_report = "\n".join(text)
markdown_report = "\n".join(markdown)
print(text_report)
(obj_root.parent / "coverage.txt").write_text(text_report + "\n", encoding="utf-8")
(obj_root.parent / "coverage.md").write_text(markdown_report + "\n", encoding="utf-8")
print(f"\nReport saved to {obj_root.parent / 'coverage.txt'} "
      f"and {obj_root.parent / 'coverage.md'}")
PY
