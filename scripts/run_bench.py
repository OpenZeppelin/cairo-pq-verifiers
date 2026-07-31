#!/usr/bin/env python3
"""Run the PQ-verifier benchmark suite and emit results/results.json.

Method: paired-test subtraction.
  verify_cost(metric) = bench_verify_<scheme>(metric) - bench_baseline_<scheme>(metric)

The two scenarios build identical inputs; only `verify` calls the verifier, so the
subtraction cancels test-harness and input-construction overhead.

Metrics come from two snforge runs:
  - default (sierra-gas) run -> accurate L2 gas
  - `--tracked-resource cairo-steps` run -> Cairo steps + per-builtin counts
    (its own l2_gas is the legacy over-estimate and is ignored)
"""
import argparse
import datetime
import json
import os
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # benchmarks/pq-verifiers
RESULTS_DIR = os.path.join(ROOT, "results")
SCHEMES_FILE = os.path.join(ROOT, "schemes.json")

CAPS = {"validate_max_steps": 1_000_000, "validate_max_l2_gas": 100_000_000}
# Source-verified from blockifier_versioned_constants_0_13_4.json (L2/Sierra gas per unit).
GAS_TABLE_L2 = {
    "step": 100, "range_check": 70, "range_check96": 56, "pedersen": 4050,
    "poseidon": 491, "bitwise": 583, "ecdsa": 10561, "ec_op": 4085,
    "keccak": 136189, "add_mod": 230, "mul_mod": 604,
}
L2_GAS_PER_CALLDATA_FELT = 5_120  # 0.128 L1 gas/felt x 40_000 L2 gas/L1 gas

PASS_RE = re.compile(
    r"\[PASS\]\s+(?P<full>[\w:]+)\s+\(l1_gas:\s*~(?P<l1>\d+),\s*"
    r"l1_data_gas:\s*~(?P<l1d>\d+),\s*l2_gas:\s*~(?P<l2>\d+)\)"
)
SIERRA_RE = re.compile(r"sierra gas:\s*(\d+)")
STEPS_RE = re.compile(r"steps:\s*(\d+)")
BUILTIN_RE = re.compile(r"Builtin\((\w+)\):\s*(\d+)")


def run_snforge(extra_args):
    cmd = [
        "snforge", "test", "bench_", "--detailed-resources",
        "--max-n-steps", "50000000",
    ] + extra_args
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return proc.stdout + "\n" + proc.stderr


def toolchain_versions():
    """The pinned toolchain, read from .tool-versions (the single source of truth)."""
    tools = {}
    with open(os.path.join(ROOT, ".tool-versions")) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2:
                tools[parts[0]] = parts[1]
    return {
        "scarb": tools.get("scarb"),
        "snforge": tools.get("starknet-foundry"),
        "cairo_profiler": tools.get("cairo-profiler"),
    }


def parse(output):
    """Parse snforge stdout into {short_test_name: {metric: value}}."""
    results = {}
    cur = None
    for line in output.splitlines():
        m = PASS_RE.search(line)
        if m:
            short = m.group("full").split("::")[-1]
            cur = results.setdefault(short, {})
            cur["l1_data_gas"] = int(m.group("l1d"))
            continue
        if cur is None:
            continue
        ms = SIERRA_RE.search(line)
        if ms:
            cur["sierra_gas"] = int(ms.group(1))
            continue
        mst = STEPS_RE.search(line)
        if mst:
            cur["steps"] = int(mst.group(1))
            continue
        if "builtins:" in line:
            cur["builtins"] = {k: int(v) for k, v in BUILTIN_RE.findall(line)}
    return results


def diff_builtins(verify, baseline):
    keys = set(verify) | set(baseline)
    out = {k: verify.get(k, 0) - baseline.get(k, 0) for k in keys}
    return {k: v for k, v in out.items() if v}


def extract_name(filename):
    """Mirror benchmark.py: contract name = from first uppercase to next dot."""
    for i, c in enumerate(filename):
        if c.isupper():
            end = filename.find(".", i)
            return filename[i:end] if end != -1 else filename[i:]
    return filename


def class_sizes():
    """Build release artifacts and measure contract-class sizes.

    Only the account-harness classes (`pqbench_targets_*`) are measured — they are the
    contracts registered in schemes.json. Other workspace packages (e.g. `pq_accounts`)
    build contracts with the same short names, so files are filtered by package prefix.
    CASM bytecode is measured in felts (`*.compiled_contract_class.json`); the Sierra class
    is measured in bytes (`*.contract_class.json`). Returns {contract_name: {felts, bytes}}.
    """
    subprocess.run(["scarb", "--release", "build"], cwd=ROOT, capture_output=True, text=True)
    target = os.path.join(ROOT, "target", "release")
    if not os.path.isdir(target):
        return {}
    out = {}
    for fname in os.listdir(target):
        if not fname.startswith("pqbench_targets_"):
            continue
        path = os.path.join(target, fname)
        if fname.endswith(".compiled_contract_class.json"):
            try:
                data = json.load(open(path))
                out.setdefault(extract_name(fname), {})["felts"] = len(data.get("bytecode", []))
            except (json.JSONDecodeError, OSError):
                pass
        elif fname.endswith(".contract_class.json"):
            out.setdefault(extract_name(fname), {})["bytes"] = os.path.getsize(path)
    return out


def main():
    parser = argparse.ArgumentParser(description="Run the PQ-verifier benchmark suite.")
    parser.add_argument("--out", default=os.path.join(RESULTS_DIR, "results.json"))
    args = parser.parse_args()

    print("Running snforge (sierra-gas mode) ...")
    sierra = parse(run_snforge([]))
    print("Running snforge (cairo-steps mode) ...")
    steps = parse(run_snforge(["--tracked-resource", "cairo-steps"]))
    print("Building contracts for class size ...")
    sizes = class_sizes()

    schemes = json.load(open(SCHEMES_FILE))["schemes"]
    rows = []
    for s in schemes:
        row = dict(s)
        if s.get("implemented"):
            vs, bs = sierra.get(s["verify_test"], {}), sierra.get(s["baseline_test"], {})
            vt, bt = steps.get(s["verify_test"], {}), steps.get(s["baseline_test"], {})
            l2 = vs.get("sierra_gas", 0) - bs.get("sierra_gas", 0)
            st = vt.get("steps", 0) - bt.get("steps", 0)
            builtins = diff_builtins(vt.get("builtins", {}), bt.get("builtins", {}))
            calldata = (s["sig_felts"] + s["pubkey_felts"]) * L2_GAS_PER_CALLDATA_FELT
            row.update({
                "measured": True,
                "verify_l2_gas": l2,
                "verify_steps": st,
                "verify_builtins": builtins,
                "calldata_l2_gas": calldata,
                "pct_of_gas_cap": round(100 * l2 / CAPS["validate_max_l2_gas"], 4),
                "pct_of_step_cap": round(100 * st / CAPS["validate_max_steps"], 4),
                "fits_gas_cap": l2 < CAPS["validate_max_l2_gas"],
                "fits_step_cap": st < CAPS["validate_max_steps"],
            })
        else:
            row["measured"] = False

        if s.get("validate_test"):
            vv = sierra.get(s["validate_test"], {})
            vb = sierra.get(s["validate_baseline_test"], {})
            vvt = steps.get(s["validate_test"], {})
            vbt = steps.get(s["validate_baseline_test"], {})
            vl2 = vv.get("sierra_gas", 0) - vb.get("sierra_gas", 0)
            vst = vvt.get("steps", 0) - vbt.get("steps", 0)
            row.update({
                "validate_l2_gas": vl2,
                "validate_steps": vst,
                "validate_pct_of_gas_cap": round(100 * vl2 / CAPS["validate_max_l2_gas"], 4),
                "validate_pct_of_step_cap": round(100 * vst / CAPS["validate_max_steps"], 4),
                "validate_fits": (
                    vl2 < CAPS["validate_max_l2_gas"] and vst < CAPS["validate_max_steps"]
                ),
            })
        if s.get("contract") and s["contract"] in sizes:
            row["class_felts"] = sizes[s["contract"]].get("felts")
            row["class_bytes"] = sizes[s["contract"]].get("bytes")
        rows.append(row)

    out = {
        "metadata": {
            "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "toolchain": toolchain_versions(),
            "caps": CAPS,
            "gas_table_l2": GAS_TABLE_L2,
            "l2_gas_per_calldata_felt": L2_GAS_PER_CALLDATA_FELT,
            "method": (
                "paired-test subtraction; L2 gas from sierra-gas mode; "
                "steps/builtins from cairo-steps mode"
            ),
        },
        "schemes": rows,
    }
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)

    print(f"\nWrote {args.out}\n")
    for r in rows:
        if r.get("measured"):
            line = (
                f"  {r['label']:30} verify {r['verify_l2_gas']:>10,} L2 gas / "
                f"{r['verify_steps']:>7,} steps"
            )
            if "validate_l2_gas" in r:
                line += (
                    f"  |  __validate__ {r['validate_l2_gas']:>10,} L2 gas "
                    f"({r['validate_pct_of_gas_cap']}% cap)"
                )
            if "class_bytes" in r:
                line += f"  |  class {r['class_bytes']:,} B"
            print(line)
        else:
            print(f"  {r['label']:30} (pending implementation)")


if __name__ == "__main__":
    main()
