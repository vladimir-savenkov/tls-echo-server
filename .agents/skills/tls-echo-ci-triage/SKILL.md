---
name: tls-echo-ci-triage
description: Diagnose failed builds, tests, or sanitizer jobs in the tls-echo-server project, including GitHub Actions ASan, TSan, and MSan failures.
---

# TLS echo CI triage

Use this skill when investigating a failing CI run, CMake build, CTest result, or sanitizer report in this repository.

1. Identify the exact commit, job, failed command, and first useful error. For GitHub runs, use the read-only GitHub Actions MCP connection if available; otherwise use available logs or GitHub CLI. Do not infer a failure from the job name alone.
2. Read `.github/workflows/ci.yml` for the current compiler, flags, environment, and test commands. Reproduce in a fresh build directory under `build/triage/` so existing build caches are preserved.
3. For ASan and TSan, run the failing CTest case or `scripts/sanitizer_smoke.py` with that job's environment. Keep ASan and TSan in separate builds. The smoke test exercises both server and client.
4. The MSan job covers `src/protocol.cpp` with `tests/test_packet.cpp` through `scripts/msan_packet_test.sh`. It needs the instrumented libc++ built in the workflow. Do not treat system-libstdc++ MSan reports as project defects without checking for uninstrumented-library false positives. The full TLS binaries are not covered by this MSan job.
5. Distinguish a compiler, dependency, runner, or test-harness failure from a report in project code. Preserve the first sanitizer stack trace and identify the source location before changing code. Fix the cause when evidence supports it; do not silence a report just to make CI pass.
6. Rerun the failing command and the relevant job path after a fix. Report the failure, evidence, change, verification, and any remaining uncertainty. Ask before rerunning a remote workflow or changing GitHub state unless that action was already authorized.
