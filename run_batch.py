"""Convenience entry point for a folder of .eml messages."""

from __future__ import annotations

import sys

from triage import main


if __name__ == "__main__":
    raise SystemExit(main(["analyze", *sys.argv[1:]]))
