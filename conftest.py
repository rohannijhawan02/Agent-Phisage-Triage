"""Make the project root importable so tests can `from src.llm import ...`."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
