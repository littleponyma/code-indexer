---
description: Generate AI-friendly panoramic code index (SQLite + JSON) for any codebase, .so, or .apk file
---

# code-indexer - Code Panorama Indexer

Analyze a codebase, shared library (.so), or APK (.apk/.apks/.xapk/.apkm) and generate a panoramic index that gives AI the full project picture in one shot — no more repeated grepping.

## Usage

```
/code-indexer <path> [options]
```

### Arguments

- `<path>` — Target: source directory, .so/.o/.a file, or .apk/.apks/.xapk/.apkm file

### Options (pass as extra args after the path)

- `--ida` — Force IDA Pro analysis for binary files
- `--no-ida` — Skip IDA analysis
- `-o DIR` — Custom output directory (default: `<target>.index/`)

## What It Does

1. **Detects input type** — source code directory, ELF/SO binary, or APK bundle
2. **Parses and indexes**:
   - **Source code**: tree-sitter for C/C++/Java, regex for Smali
   - **SO files**: lief + pyelftools for ELF symbols/strings/relocations; optional IDA (idalib/NO-MCP) for deep analysis
   - **APK files**: androguard APK + DEX low-level APIs (no AnalyzeAPK, no get_xref_*)
3. **Stores structured index** in SQLite (`index.db`) with tables for files, symbols, calls, imports, xrefs, strings
4. **Generates**:
   - `panorama.json` — AI-consumable summary with architecture, call graph, entry points, hot functions, highlights
   - `panorama.md` — Human-readable report
   - `index.db` — Queryable SQLite database for deep dives

## After Indexing

Read the `panorama.json` for the full project picture. Query the SQLite database for specific details:

```sql
-- Find all callers of a function
SELECT caller_name, call_type FROM calls WHERE callee_name = 'target_func';

-- Find all functions in a file
SELECT s.name, s.type, s.line, s.signature
FROM symbols s JOIN files f ON s.file_id = f.id
WHERE f.path = 'src/main.c';

-- Find entry points
SELECT name, address, signature FROM symbols WHERE is_entry_point = 1;

-- Hot functions (most called)
SELECT callee_name, COUNT(*) as callers FROM calls GROUP BY callee_name ORDER BY callers DESC LIMIT 20;

-- Find strings containing keywords
SELECT value, address FROM strings WHERE value LIKE '%password%' OR value LIKE '%key%';

-- Find JNI native methods
SELECT name, address FROM symbols WHERE name LIKE 'Java_%';
```

## IDA Integration

For .so files, the indexer supports three IDA backends (in priority order):

1. **idalib** — Direct Python binding to IDA analysis engine, runs INP.py export script headlessly
2. **ida-no-mcp** — Reads pre-exported `decompile/*.c` + `imports.txt`/`exports.txt`/`strings.txt`

## Examples

```
/code-indexer /path/to/project          # Analyze a source directory
/code-indexer /path/to/libnative.so     # Analyze an ELF shared library
/code-indexer /path/to/app.apk          # Analyze an APK
/code-indexer /path/to/app.xapk         # Analyze a split APK bundle
/code-indexer /path/to/lib.so --ida     # Force IDA analysis for deeper results
```

## Implementation

The indexer is implemented in Python at `D:/workspace/code-reviewer/indexer/`.

To run directly:
```bash
python -m indexer.cli <path> [options]
```