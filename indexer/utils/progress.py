"""Logging and progress utilities."""

from __future__ import annotations

import sys
import time


class Progress:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.start_time = time.time()

    def log(self, msg: str):
        print(f"[code-indexer] {msg}")

    def verbose_log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")

    def error(self, msg: str):
        print(f"[code-indexer ERROR] {msg}", file=sys.stderr)

    def elapsed(self) -> str:
        seconds = int(time.time() - self.start_time)
        if seconds < 60:
            return f"{seconds}s"
        return f"{seconds // 60}m {seconds % 60}s"
