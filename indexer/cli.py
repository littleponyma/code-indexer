"""CLI entry point for the code indexer."""

from __future__ import annotations

import argparse
import sys

from .core import index_target


def main():
    parser = argparse.ArgumentParser(
        prog="code-indexer",
        description="Generate AI-friendly panoramic code index (SQLite + JSON) for codebases, .so, or .apk files",
    )
    parser.add_argument("path", help="Target path: source directory, .so file, or .apk/.apks/.xapk/.apkm file")
    parser.add_argument("-o", "--output-dir", default=None, help="Output directory (default: <target>.index)")
    parser.add_argument("--ida", action="store_true", help="Force use IDA for binary analysis")
    parser.add_argument("--no-ida", action="store_true", help="Skip IDA analysis")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Call chain drill depth (default: 3)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--max-functions", type=int, default=0, help="Max functions to decompile via IDA (0=unlimited, default: 0)")

    args = parser.parse_args()

    try:
        result = index_target(
            path=args.path,
            output_dir=args.output_dir,
            use_ida=args.ida,
            no_ida=args.no_ida,
            depth=args.depth,
            verbose=args.verbose,
        )
        if result:
            print(f"\nIndexing complete!")
            print(f"  Database: {result['db_path']}")
            print(f"  Summary:  {result['json_path']}")
            print(f"  Report:   {result['md_path']}")
        else:
            print("Indexing failed.", file=sys.stderr)
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
