#!/usr/bin/env python3
"""Generate the SLH-DSA-SHAKE-128s benchmark fixture.

The generator drives the slh-dsa/slhdsa-c FIPS 205 implementation, using fixed
test-only seeds and deterministic pure signing over the 32-byte big-endian
`BENCH_MSG` field value with an empty context. It asks the reference executable
to verify the result before emitting the Cairo fixture.

Usage:
    python3 scripts/gen_slh_dsa_shake_fixture.py --slhdsa-c /path/to/slhdsa-c
"""

import argparse
import hashlib
import re
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "crates/slh_dsa_shake_128s/src/fixtures.cairo"
PARAMETER_SET = "SLH-DSA-SHAKE-128s"
MESSAGE_LABEL = "BENCH_MSG"


def seed(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:32].upper()


def run(executable: Path, args: list[str]) -> str:
    proc = subprocess.run(
        [str(executable), *args],
        cwd=executable.parent,
        check=True,
        capture_output=True,
        text=True,
    )
    if "[PASS]" not in proc.stdout:
        raise RuntimeError(proc.stdout + proc.stderr)
    return proc.stdout


def value(output: str, name: str) -> str:
    match = re.search(rf"^{name} = ([0-9A-F]+)$", output, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"missing {name} in reference output")
    return match.group(1)


def chunks(hex_data: str, size: int = 32) -> list[str]:
    assert len(hex_data) % size == 0
    return [hex_data[i : i + size] for i in range(0, len(hex_data), size)]


def cairo_values(hex_data: str) -> str:
    values = [f"0x{chunk.lower()}," for chunk in chunks(hex_data)]
    return "\n".join(f"        {' '.join(values[i : i + 2])}" for i in range(0, len(values), 2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--slhdsa-c",
        type=Path,
        required=True,
        help="path to a slh-dsa/slhdsa-c clone",
    )
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()

    source = args.slhdsa_c.resolve()
    executable = source / "xfips205"
    if not executable.exists():
        subprocess.run(["make"], cwd=source, check=True)

    sk_seed = seed("cairo-pq-verifiers SLH-DSA sk seed")
    sk_prf = seed("cairo-pq-verifiers SLH-DSA sk prf")
    pk_seed = seed("cairo-pq-verifiers SLH-DSA pk seed")
    keygen = run(
        executable,
        [
            "-parameterSet",
            PARAMETER_SET,
            "-skSeed",
            sk_seed,
            "-skPrf",
            sk_prf,
            "-pkSeed",
            pk_seed,
            "keyGen",
        ],
    )
    public_key = value(keygen, "pk")
    secret_key = value(keygen, "sk")

    message_value = int.from_bytes(MESSAGE_LABEL.encode(), "big")
    message = message_value.to_bytes(32, "big").hex().upper()
    siggen = run(
        executable,
        [
            "-parameterSet",
            PARAMETER_SET,
            "-message",
            message,
            "-sk",
            secret_key,
            "-signatureInterface",
            "external",
            "-preHash",
            "False",
            "sigGen",
        ],
    )
    signature = value(siggen, "sig")
    run(
        executable,
        [
            "-parameterSet",
            PARAMETER_SET,
            "-message",
            message,
            "-pk",
            public_key,
            "-signature",
            signature,
            "-signatureInterface",
            "external",
            "-preHash",
            "False",
            "-testPassed",
            "True",
            "sigVer",
        ],
    )

    assert len(public_key) == 64
    assert len(signature) == 15_712
    output = f"""//! Generated SLH-DSA-SHAKE-128s benchmark fixture.
//!
//! This is a deterministic pure FIPS 205 signature with an empty context over the
//! 32-byte big-endian encoding of `{MESSAGE_LABEL}`. Regenerate it with
//! `scripts/gen_slh_dsa_shake_fixture.py`.

/// The transaction-hash field signed by the fixture.
pub fn message() -> felt252 {{
    {message_value}
}}

/// `PK.seed || PK.root`, one 16-byte value per felt.
pub fn public_key() -> Array<felt252> {{
    array![{", ".join(f"0x{chunk.lower()}" for chunk in chunks(public_key))}]
}}

/// `R || SIG_FORS || SIG_HT`, one 16-byte value per felt.
pub fn signature() -> Array<felt252> {{
    array![
{cairo_values(signature)}
    ]
}}
"""
    args.out.write_text(output)
    print(f"wrote {args.out} ({len(chunks(signature))} signature felts)")


if __name__ == "__main__":
    main()
