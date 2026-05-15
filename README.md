# Code Indexer

AI-friendly panoramic code indexer — generate a structured index (SQLite + JSON) for any codebase, `.so`, or `.apk` file, giving AI the full project picture in one shot.

No more repeated grepping. AI reads `panorama.json` and queries `index.db` to understand architecture, call chains, entry points, and more.

## Features

- **Source code**: tree-sitter for C/C++/Java, regex for Smali
- **ELF/SO**: lief + pyelftools for symbols/strings/relocations; IDA (idalib) for deep decompilation
- **APK**: androguard APK + DEX low-level APIs — supports `.apk`, `.apks`, `.xapk`, `.apkm`
- **IDA Integration**: idalib loads the binary headlessly, runs [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP) export script to decompile all functions, then parses the results
- **Streaming DB writes**: noise filtering, dedup, string truncation — keeps DB size manageable even for large binaries
- **Output**: SQLite database (`index.db`) + AI-consumable JSON summary (`panorama.json`) + human-readable Markdown report (`panorama.md`)

## Install

### One-click installer

**Windows:**

```batch
install.bat
```

**macOS / Linux:**

```bash
chmod +x install.sh
./install.sh
```

The installer will:
1. Check Python 3.10+ is available
2. Install all Python dependencies
3. Copy the Claude Code skill to `~/.claude/skills/code-indexer/`
4. Check IDA Pro idalib availability (optional)
5. Verify the installation

### Manual install

```bash
pip install -r requirements.txt

# Install Claude Code skill
mkdir -p ~/.claude/skills/code-indexer
cp .claude/skills/code-indexer/* ~/.claude/skills/code-indexer/
```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| tree-sitter | >=0.23 | Source code parsing framework |
| tree-sitter-c | >=0.23 | C language grammar |
| tree-sitter-cpp | >=0.23 | C++ language grammar |
| tree-sitter-java | >=0.23 | Java language grammar |
| lief | >=0.14 | ELF/SO binary parsing |
| pyelftools | >=0.31 | DWARF debug info |
| androguard | >=4.1 | APK/DEX parsing |
| capstone | >=5.0 | Disassembly engine |
| idapro | optional | IDA Pro 9 idalib for deep binary analysis |

### Tested Environments

| OS | Python | Status |
|----|--------|--------|
| Windows 11 | Python 3.13.5 | Tested |
| macOS 14 (Sonoma) | Python 3.12 | Tested |
| Ubuntu 22.04 | Python 3.10 | Tested |

## Usage

### Claude Code Skill

```
/code-indexer /path/to/project
/code-indexer /path/to/libnative.so
/code-indexer /path/to/app.apk
/code-indexer /path/to/lib.so --ida
```

### CLI

```bash
python -m indexer.cli <path> [options]
```

Options:
| Flag | Description |
|------|-------------|
| `--ida` | Force IDA Pro analysis for binary files |
| `--no-ida` | Skip IDA analysis |
| `-o DIR` | Custom output directory (default: `<target>.index/`) |
| `-d DEPTH` | Call chain drill depth (default: 3) |
| `-v` | Verbose output |

### Examples

```bash
# Analyze a source directory
python -m indexer.cli /path/to/project

# Analyze an ELF shared library
python -m indexer.cli /path/to/libnative.so

# Analyze an APK (also supports .xapk, .apks, .apkm)
python -m indexer.cli /path/to/app.apk

# Force IDA analysis for deeper results
python -m indexer.cli /path/to/lib.so --ida
```

## Output

After indexing, the output directory contains:

| File | Description |
|------|-------------|
| `index.db` | SQLite database with full structured index |
| `panorama.json` | AI-consumable summary — architecture, call graph, entry points, hot functions |
| `panorama.md` | Human-readable Markdown report |

### Querying the Database

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

For `.so` files, the indexer supports IDA-based deep analysis:

1. **idalib** — Direct Python binding to IDA analysis engine. Opens the binary headlessly, runs the [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP) `INP.py` export script to decompile all functions, then parses the results into the index.
2. **ida-no-mcp** — Reads pre-exported `decompile/*.c` + `imports.txt`/`exports.txt`/`strings.txt` from a directory next to the binary (if you already ran the export manually).

Priority: idalib (if available) > ida-no-mcp (if export data exists) > lief-only fallback.

### IDA-NO-MCP Plugin

The [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP) plugin (`INP.py`) is bundled with this skill. It exports:

| Output | Content |
|--------|---------|
| `decompile/*.c` | Decompiled C code per function (with callers/callees metadata) |
| `disassembly/*.asm` | Disassembly fallback for functions that fail decompilation |
| `imports.txt` | Import table |
| `exports.txt` | Export table |
| `strings.txt` | String table |
| `pointers.txt` | Pointer references |
| `memory/` | Memory hexdump by segment |

## Architecture

```
indexer/
├── cli.py              # CLI entry point
├── core.py             # Main orchestration
├── db.py               # SQLite layer (streaming writes, noise filter, dedup)
├── models.py           # Data models
├── detectors/
│   └── detector.py     # Input type detection (source/so/apk)
├── parsers/
│   ├── source_parser.py # tree-sitter C/C++/Java, regex Smali
│   ├── elf_parser.py    # lief + pyelftools
│   ├── apk_parser.py    # androguard APK + DEX
│   └── ida_parser.py    # idalib -> INP.py -> parse exports
├── analyzers/
│   ├── call_graph.py    # Call graph analysis
│   ├── arch_detector.py # Architecture pattern detection
│   └── summary.py       # JSON + Markdown generation
└── utils/
    └── progress.py      # Progress logging
```

## License

MIT
