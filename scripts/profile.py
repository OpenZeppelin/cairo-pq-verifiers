#!/usr/bin/env python3
"""Augment results/results.json with per-function step attribution via cairo-profiler.

For each measured scheme it regenerates the verify trace in cairo-steps mode, builds a
profile, and parses `cairo-profiler view --sample steps` into a flat per-function list
("where the steps go inside verify"). Most useful once a real verifier exists (e.g. Falcon:
NTT vs hash-to-point vs norm check). Run after run_bench.py and before gen_report.py.

Requires cairo-profiler >= 0.16 (0.8 cannot parse Sierra 1.8 / cairo 2.18).
"""
import glob
import json
import os
import re
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(ROOT, "results", "results.json")

FLAT_RE = re.compile(r'^\s*(\d+)\s+steps\s+\|\s*([\d.]+)%.*\|\s*"(.+)"\s*$')
# Functions that are test-harness framing rather than the verifier itself.
HARNESS = ("snforge", "SNFORGE_TEST_CODE", "cheatcode", "ResultSerde", "__snforge")
MAX_PROFILE_STEPS = 5_000_000


def clear_traces():
    """Remove stale trace directories so every profile reads a trace from this run."""
    for d in glob.glob(os.path.join(ROOT, "crates", "*", "snfoundry_trace")):
        shutil.rmtree(d, ignore_errors=True)


def trace_path(test):
    """The trace for exactly `test`: snforge writes one file per test, named after the
    full test path with `::` replaced by `_`, so the module prefix always ends with an
    underscore before the test name. Substring-named tests (e.g. `<test>_shake`) do not
    match; if several modules define the same short name, take the newest trace."""
    hits = glob.glob(os.path.join(ROOT, "crates", "*", "snfoundry_trace", f"*_{test}.json"))
    return max(hits, key=os.path.getmtime) if hits else None


def profile_scheme(scheme):
    subprocess.run(
        ["snforge", "test", scheme["verify_test"], "--save-trace-data",
         "--tracked-resource", "cairo-steps", "--max-n-steps", "50000000"],
        cwd=ROOT, capture_output=True, text=True,
    )
    tp = trace_path(scheme["verify_test"])
    if not tp:
        return None
    prof = f"/tmp/pqbench_{scheme['key']}.pb.gz"
    subprocess.run(
        ["cairo-profiler", "build-profile", tp, "--output-path", prof],
        cwd=ROOT, capture_output=True, text=True,
    )
    view = subprocess.run(
        ["cairo-profiler", "view", prof, "--sample", "steps", "--limit", "25"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout
    funcs = []
    for line in view.splitlines():
        m = FLAT_RE.match(line)
        if not m:
            continue
        name = m.group(3).replace("\\n", " ").strip()
        funcs.append({
            "function": name,
            "flat_steps": int(m.group(1)),
            "flat_pct": float(m.group(2)),
            "harness": any(h in name for h in HARNESS),
        })
    return funcs


def main():
    clear_traces()
    data = json.load(open(RESULTS))
    for s in data["schemes"]:
        if not s.get("measured"):
            continue
        if s.get("verify_steps", 0) > MAX_PROFILE_STEPS:
            print(
                f"Skipping {s['label']} profile: {s['verify_steps']:,} steps exceeds "
                f"the {MAX_PROFILE_STEPS:,}-step trace budget"
            )
            continue
        funcs = profile_scheme(s)
        if funcs is not None:
            s["verify_profile"] = funcs
    with open(RESULTS, "w") as f:
        json.dump(data, f, indent=2)
    print("Augmented results.json with cairo-profiler step attribution")
    for s in data["schemes"]:
        if s.get("verify_profile"):
            print(f"  {s['label']}:")
            for fn in [x for x in s["verify_profile"] if not x["harness"]][:5]:
                print(f"    {fn['flat_steps']:>5} steps {fn['flat_pct']:>6}%  {fn['function']}")


if __name__ == "__main__":
    main()
