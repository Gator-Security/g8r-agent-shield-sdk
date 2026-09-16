#!/usr/bin/env python3
"""Generate fixtures, compile the TypeScript verifier, and run receipt tests."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--type-roots", type=Path, help="Parent of installed @types/node (optional)")
    args = parser.parse_args()

    subprocess.run([sys.executable, str(ROOT / "tools/generate_receipt_vectors.py")], check=True, cwd=ROOT)

    compiler_candidates = [
        ROOT / "js/node_modules/.bin/tsc",
        ROOT / "tools/receipt-tests/node_modules/.bin/tsc",
    ]
    tsc = next((str(candidate) for candidate in compiler_candidates if candidate.is_file()), shutil.which("tsc"))
    if not tsc or not shutil.which("node"):
        parser.error("Install Node and TypeScript; in the SDK repository run npm ci in js/")

    roots = args.type_roots
    if roots is None:
        for candidate in (
            ROOT / "js/node_modules/@types",
            ROOT / "tools/receipt-tests/node_modules/@types",
            ROOT / "node_modules/@types",
        ):
            if (candidate / "node").is_dir():
                roots = candidate
                break
    if roots is None:
        parser.error("Cannot locate @types/node; provide --type-roots or install JS dev dependencies")

    with tempfile.TemporaryDirectory(prefix="g8r-receipt-tests-") as directory:
        build = Path(directory)
        command = [
            tsc,
            "--strict",
            "--target", "ES2020",
            "--module", "commonjs",
            "--moduleResolution", "node",
            "--types", "node",
            "--typeRoots", str(roots),
            "--outDir", str(build),
            str(ROOT / "js/src/receipts.ts"),
        ]
        subprocess.run(command, check=True, cwd=ROOT)
        environment = {**os.environ, "G8R_RECEIPTS_JS": str(build / "receipts.js")}
        subprocess.run(
            ["node", "--test", str(ROOT / "tests/receipts.test.cjs")],
            check=True, env=environment, cwd=ROOT,
        )
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", str(ROOT / "tests/test_receipts.py")],
            check=True, env=environment, cwd=ROOT,
        )
        print("Receipt vector generation, TypeScript compile, Node tests, Python tests, and live mock interoperability passed.")


if __name__ == "__main__":
    main()
