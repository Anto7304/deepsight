#!/usr/bin/env python3
"""Prepare external operator files without changing application data."""
import argparse
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "samples/scenario")
    parser.add_argument("--prefix", default=os.getenv("ASIVM_LAB_PREFIX", "172.28.50"))
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--feed-url")
    parser.add_argument("--verification-only", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    with tempfile.TemporaryDirectory(prefix="deepsight-import-files-") as scratch:
        os.environ.update(ASIVM_DATA_DIR=scratch, ASIVM_DATABASE_URL="sqlite://", ASIVM_SECRET_KEY="import-file-builder-unused-secret")
        from scenario_files import build
        build(args.output, args.prefix, args.local, args.feed_url, args.verification_only)
    print(f"Import files: {args.output.resolve()}")


if __name__ == "__main__":
    main()
