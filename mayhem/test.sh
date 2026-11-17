#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's libcheck unit suite (unittests/: queue, buffer, hmac, route, dedup, wire), built by
# build.sh into build/tests. libcheck prints "<pct>%: Checks: N, Failures: F, Errors: E"; each check
# asserts values (ck_assert_*), e.g. HMAC known answers and header encode/decode round trips.
runner=build/tests/unittests/csp_tests
if [ ! -x "$runner" ]; then
  echo "test.sh: $runner missing — mayhem/build.sh did not build the suite" >&2
  emit_ctrf "libcheck" 0 1 0
  exit 1
fi
log=$(mktemp)
"$runner" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
line=$(grep -E '^[0-9]+%: Checks: [0-9]+, Failures: [0-9]+, Errors: [0-9]+' "$log" | tail -1)
rm -f "$log"
if [ -z "$line" ]; then
  echo "test.sh: no libcheck summary in the runner output (exit $rc)" >&2
  emit_ctrf "libcheck" 0 1 0
  exit 1
fi
checks=$(sed -E 's/.*Checks: ([0-9]+).*/\1/' <<<"$line")
failures=$(sed -E 's/.*Failures: ([0-9]+).*/\1/' <<<"$line")
errors=$(sed -E 's/.*Errors: ([0-9]+).*/\1/' <<<"$line")
failed=$(( failures + errors ))
passed=$(( checks - failed ))
if [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; then failed=1; fi
emit_ctrf "libcheck" "$passed" "$failed" 0
