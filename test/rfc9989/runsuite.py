#!/usr/bin/env python3
"""Drive the RFC 9989 Appendix B examples against `securedmarc-check`.

Each case brings its own DNS zone, which is served on a loopback port by
`dmarcdns.DmarcDns` so the daemon's own resolver does the lookups. Nothing is
stubbed inside `securedmarc`: the checker calls the same `treewalk.walk`,
`treewalk.organizationalDomain`, `treewalk.orgWalk`, `dmarc.evaluate` and
`dmarc.getDisposition` that the milter's `onEom` calls.

Exit status is non-zero if any case fails, so this can gate a build.

    python3 runsuite.py                 # run everything
    python3 runsuite.py -v              # list every case
    python3 runsuite.py --test NAME     # one case
    python3 runsuite.py --section B.4   # cases whose section starts with B.4
    SECUREDMARC_CHECK=/path/to/binary python3 runsuite.py
"""

import argparse
import os
import subprocess
import sys

from dmarcdns import DmarcDns
from cases import ALL_CASES

DEFAULT_CHECK = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "zig-out", "bin",
    "securedmarc-check",
)
DEFAULT_PORT = 5355


def parse_output(text):
    """Turn the checker's key=value lines into a dict."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def run_case(case, check_bin, port, verbose):
    """Run one case. Returns (ok, list_of_problem_strings)."""
    problems = []
    with DmarcDns(case.get("zone"), port, verbose=verbose) as dns:
        cmd = [check_bin, "-n", "127.0.0.1", "-p", str(port)] + case["args"]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            return False, ["checker timed out"]

        if proc.returncode != 0:
            return False, [
                f"checker exited {proc.returncode}: "
                f"{proc.stderr.decode(errors='replace').strip()[:200]}"
            ]

        got = parse_output(proc.stdout.decode(errors="replace"))

        for key, want in case.get("expect", {}).items():
            if key not in got:
                problems.append(f"{key}: missing from output")
            elif got[key] != want:
                problems.append(f"{key}: want {want!r} got {got[key]!r}")

        want_queries = case.get("expect_queries")
        if want_queries is not None:
            actual = dns.distinct_queries()
            if actual != want_queries:
                problems.append(
                    "queries differ\n"
                    f"        want: {want_queries}\n"
                    f"        got:  {actual}"
                )

    return not problems, problems


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every case, and log DNS queries")
    ap.add_argument("--test", metavar="NAME", help="run only this case")
    ap.add_argument("--section", metavar="PREFIX",
                    help="run cases whose RFC section starts with PREFIX")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"loopback DNS port (default {DEFAULT_PORT})")
    ap.add_argument("--check", default=os.environ.get("SECUREDMARC_CHECK", DEFAULT_CHECK),
                    help="path to securedmarc-check")
    args = ap.parse_args()

    check_bin = os.path.abspath(args.check)
    if not os.path.isfile(check_bin):
        print(f"securedmarc-check not found at {check_bin}\n"
              f"Build it first:  cd ../.. && zig build", file=sys.stderr)
        return 2

    selected = ALL_CASES
    if args.test:
        selected = [c for c in selected if c["name"] == args.test]
    if args.section:
        selected = [c for c in selected if c["section"].startswith(args.section)]
    if not selected:
        print("no cases selected", file=sys.stderr)
        return 2

    passed = 0
    failures = []
    for case in selected:
        ok, problems = run_case(case, check_bin, args.port, args.verbose)
        if ok:
            passed += 1
            if args.verbose:
                print(f"  PASS  {case['name']:<32} [{case['section']}]")
        else:
            failures.append((case, problems))
            print(f"  FAIL  {case['name']:<32} [{case['section']}]")
            for p in problems:
                print(f"        {p}")

    total = len(selected)
    print(f"\ntotal={total} passed={passed} failed={len(failures)}")

    if failures:
        print("\nfailing cases, with the RFC text that fixes each expectation:")
        for case, problems in failures:
            print(f"\n  {case['name']}  [RFC 9989 {case['section']}]")
            print(f"    RFC: {case['source']}")
            if case.get("note"):
                print(f"    note: {case['note']}")
            for p in problems:
                print(f"    -> {p}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
