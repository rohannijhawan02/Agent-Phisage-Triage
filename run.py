"""Convenience entry point for one .eml; writes the analyst report to results/."""

from __future__ import annotations

import sys

from triage import main


if __name__ == "__main__":
    raise SystemExit(main(["analyze", *sys.argv[1:]]))
