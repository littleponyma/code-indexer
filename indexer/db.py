"""SQLite database layer for the code indexer.

Streaming writes with dedup and noise filtering to keep DB size manageable.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Generator, Iterable, Optional

from .models import (
    CallRelation,
    FileEntry,
    ImportEntry,
    ProjectMeta,
    SourceType,
    StringEntry,
    Symbol,
    SymbolType,
    XrefEntry,
    Importance,
    CallType,
)

# Noise filter: skip these class packages in DEX
_NOISE_PREFIXES = (
    "android.", "androidx.", "java.", "javax.", "kotlin.",
    "kotlinx.", "com.google.android.", "dalvik.",
    "org.apache.http.", "org.intellij.", "org.jetbrains.",
)

MAX_STRING_LEN = 1024  # Truncate strings longer than this
FLUSH_EVERY = 5000     # Commit every N rows for streaming writes

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS project_meta (
    id INTEGER PRIMARY KEY,
    source_path TEXT NOT NULL,
    source_type TEXT NOT NULL,
    scan_time TEXT NOT NULL,
    total_files INTEGER DEFAULT 0,
    total_symbols INTEGER DEFAULT 0,
    total_calls INTEGER DEFAULT 0,
    language_breakdown TEXT,
    tool_used TEXT,
    extra_meta TEXT
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    language TEXT,
    size INTEGER,
    symbol_count INTEGER DEFAULT 0,
    is_entry_point INTEGER DEFAULT 0,
    module TEXT,
    UNIQUE(path)
);

CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    full_name TEXT,
    type TEXT NOT NULL,
    file_id INTEGER REFERENCES files(id),
    address TEXT,
    line INTEGER,
    end_line INTEGER,
    signature TEXT,
    is_exported INTEGER DEFAULT 0,
    is_imported INTEGER DEFAULT 0,
    is_entry_point INTEGER DEFAULT 0,
    importance TEXT DEFAULT 'medium',
    description TEXT,
    module TEXT,
    extra TEXT
);

CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY,
    caller_id INTEGER REFERENCES symbols(id),
    callee_id INTEGER REFERENCES symbols(id),
    caller_name TEXT NOT NULL,
    callee_name TEXT NOT NULL,
    call_type TEXT DEFAULT 'direct',
    file_id INTEGER REFERENCES files(id),
    line INTEGER,
    address TEXT,
    UNIQUE(caller_name, callee_name, address)
);

CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY,
    file_id INTEGER REFERENCES files(id),
    target TEXT NOT NULL,
    import_type TEXT,
    line INTEGER
);

CREATE TABLE IF NOT EXISTS xrefs (
    id INTEGER PRIMARY KEY,
    from_symbol_id INTEGER REFERENCES symbols(id),
    to_symbol_id INTEGER REFERENCES symbols(id),
    from_address TEXT,
    to_address TEXT,
    xref_type TEXT
);

CREATE TABLE IF NOT EXISTS strings (
    id INTEGER PRIMARY KEY,
    address TEXT,
    value TEXT NOT NULL,
    encoding TEXT DEFAULT 'utf-8',
    length INTEGER,
    referenced_by INTEGER REFERENCES symbols(id),
    UNIQUE(value)
);

CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_type ON symbols(type);
CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_id);
CREATE INDEX IF NOT EXISTS idx_symbols_address ON symbols(address);
CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_id);
CREATE INDEX IF NOT EXISTS idx_calls_caller_name ON calls(caller_name);
CREATE INDEX IF NOT EXISTS idx_calls_callee_name ON calls(callee_name);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(from_symbol_id);
CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(to_symbol_id);
"""

# Strings table index created separately (after bulk insert) for performance
_STRINGS_INDEX_SQL = "CREATE INDEX IF NOT EXISTS idx_strings_value ON strings(value);"


def is_noise_class(class_name: str) -> bool:
    """Check if a class name belongs to framework/boilerplate noise."""
    return any(class_name.startswith(p) for p in _NOISE_PREFIXES)


def truncate_string(value: str) -> str:
    if len(value) > MAX_STRING_LEN:
        return value[:MAX_STRING_LEN] + "..."
    return value


class IndexDatabase:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-65536")  # 64MB cache
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()
        self._pending = 0

    def _create_tables(self):
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def _maybe_flush(self):
        self._pending += 1
        if self._pending >= FLUSH_EVERY:
            self.conn.commit()
            self._pending = 0

    def flush(self):
        if self._pending > 0:
            self.conn.commit()
            self._pending = 0

    def finalize(self):
        """Create deferred indexes and optimize after bulk inserts."""
        self.flush()
        self.conn.execute(_STRINGS_INDEX_SQL)
        self.conn.execute("ANALYZE")
        self.conn.commit()

    def close(self):
        self.finalize()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # --- Project Meta ---

    def insert_meta(self, meta: ProjectMeta) -> int:
        cur = self.conn.execute(
            """INSERT INTO project_meta
               (source_path, source_type, scan_time, total_files, total_symbols,
                total_calls, language_breakdown, tool_used, extra_meta)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                meta.source_path, meta.source_type.value, meta.scan_time,
                meta.total_files, meta.total_symbols, meta.total_calls,
                json.dumps(meta.language_breakdown) if meta.language_breakdown else None,
                meta.tool_used,
                json.dumps(meta.extra_meta) if meta.extra_meta else None,
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_meta_stats(self, meta_id: int, total_files: int, total_symbols: int, total_calls: int):
        self.conn.execute(
            "UPDATE project_meta SET total_files=?, total_symbols=?, total_calls=? WHERE id=?",
            (total_files, total_symbols, total_calls, meta_id),
        )
        self.conn.commit()

    # --- Streaming inserts ---

    def insert_file(self, f: FileEntry) -> int:
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO files (path, language, size, symbol_count, is_entry_point, module)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (f.path, f.language, f.size, f.symbol_count, int(f.is_entry_point), f.module),
        )
        self._maybe_flush()
        if cur.lastrowid:
            return cur.lastrowid
        row = self.conn.execute("SELECT id FROM files WHERE path=?", (f.path,)).fetchone()
        return row[0]

    def get_file_id(self, path: str) -> Optional[int]:
        row = self.conn.execute("SELECT id FROM files WHERE path=?", (path,)).fetchone()
        return row[0] if row else None

    def stream_symbols(self, symbols: Iterable[Symbol]):
        """Stream symbols into DB, filtering noise."""
        for s in symbols:
            # Skip noise classes (framework boilerplate)
            if s.full_name and is_noise_class(s.full_name):
                continue
            if s.type == SymbolType.FIELD and s.importance == Importance.LOW and s.full_name and is_noise_class(s.full_name):
                continue

            self.conn.execute(
                """INSERT INTO symbols
                   (name, full_name, type, file_id, address, line, end_line, signature,
                    is_exported, is_imported, is_entry_point, importance, description, module, extra)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    s.name, s.full_name, s.type.value, s.file_id, s.address, s.line,
                    s.end_line, s.signature, int(s.is_exported), int(s.is_imported),
                    int(s.is_entry_point), s.importance.value, s.description, s.module,
                    json.dumps(s.extra) if s.extra else None,
                ),
            )
            self._maybe_flush()

    def stream_calls(self, calls: Iterable[CallRelation]):
        """Stream calls into DB with dedup via UNIQUE constraint."""
        for c in calls:
            # Skip calls where both caller and callee are noise
            if (is_noise_class(c.caller_name) and is_noise_class(c.callee_name)):
                continue

            try:
                self.conn.execute(
                    """INSERT OR IGNORE INTO calls
                       (caller_id, callee_id, caller_name, callee_name, call_type, file_id, line, address)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        c.caller_id, c.callee_id, c.caller_name, c.callee_name,
                        c.call_type.value, c.file_id, c.line, c.address,
                    ),
                )
            except sqlite3.IntegrityError:
                pass  # Duplicate, skip
            self._maybe_flush()

    def stream_strings(self, strings: Iterable[StringEntry]):
        """Stream strings into DB with dedup and truncation."""
        for s in strings:
            value = truncate_string(s.value)
            try:
                self.conn.execute(
                    "INSERT OR IGNORE INTO strings (address, value, encoding, length, referenced_by) VALUES (?, ?, ?, ?, ?)",
                    (s.address, value, s.encoding, s.length, s.referenced_by),
                )
            except sqlite3.IntegrityError:
                pass  # Duplicate value, skip
            self._maybe_flush()

    def stream_imports(self, imports: Iterable[ImportEntry]):
        for i in imports:
            self.conn.execute(
                "INSERT INTO imports (file_id, target, import_type, line) VALUES (?, ?, ?, ?)",
                (i.file_id, i.target, i.import_type, i.line),
            )
            self._maybe_flush()

    def stream_xrefs(self, xrefs: Iterable[XrefEntry]):
        for x in xrefs:
            self.conn.execute(
                """INSERT INTO xrefs (from_symbol_id, to_symbol_id, from_address, to_address, xref_type)
                   VALUES (?, ?, ?, ?, ?)""",
                (x.from_symbol_id, x.to_symbol_id, x.from_address, x.to_address, x.xref_type),
            )
            self._maybe_flush()

    # --- Symbol ID resolution (called after all symbols are inserted) ---

    def resolve_symbol_ids(self, calls: list[CallRelation]):
        name_to_id: dict[str, int] = {}
        for row in self.conn.execute("SELECT name, id FROM symbols"):
            name_to_id[row[0]] = row[1]
        for call in calls:
            call.caller_id = name_to_id.get(call.caller_name)
            call.callee_id = name_to_id.get(call.callee_name)

    # --- Batch inserts (kept for small datasets, delegates to streaming) ---

    def insert_symbols_batch(self, symbols: list[Symbol]):
        self.stream_symbols(symbols)
        self.flush()

    def insert_calls_batch(self, calls: list[CallRelation]):
        self.stream_calls(calls)
        self.flush()

    def insert_strings_batch(self, strings: list[StringEntry]):
        self.stream_strings(strings)
        self.flush()

    def insert_imports_batch(self, imports: list[ImportEntry]):
        self.stream_imports(imports)
        self.flush()

    def insert_xrefs_batch(self, xrefs: list[XrefEntry]):
        self.stream_xrefs(xrefs)
        self.flush()

    # --- Query helpers ---

    def query_callers(self, func_name: str) -> list[dict]:
        rows = self.conn.execute(
            """SELECT c.caller_name, c.call_type, f.path, c.line, c.address
               FROM calls c LEFT JOIN files f ON c.file_id = f.id
               WHERE c.callee_name=?""",
            (func_name,),
        ).fetchall()
        return [
            {"caller": r[0], "call_type": r[1], "file": r[2], "line": r[3], "address": r[4]}
            for r in rows
        ]

    def query_callees(self, func_name: str) -> list[dict]:
        rows = self.conn.execute(
            """SELECT c.callee_name, c.call_type, f.path, c.line, c.address
               FROM calls c LEFT JOIN files f ON c.file_id = f.id
               WHERE c.caller_name=?""",
            (func_name,),
        ).fetchall()
        return [
            {"callee": r[0], "call_type": r[1], "file": r[2], "line": r[3], "address": r[4]}
            for r in rows
        ]

    def query_hot_functions(self, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            """SELECT callee_name, COUNT(*) as cnt FROM calls
               GROUP BY callee_name ORDER BY cnt DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [{"name": r[0], "callers": r[1]} for r in rows]

    def query_entry_points(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT name, full_name, type, address, signature, description FROM symbols WHERE is_entry_point=1"
        ).fetchall()
        return [
            {"name": r[0], "full_name": r[1], "type": r[2], "address": r[3], "signature": r[4], "description": r[5]}
            for r in rows
        ]

    def query_leaf_functions(self, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            """SELECT s.name, f.path FROM symbols s
               LEFT JOIN files f ON s.file_id = f.id
               WHERE s.type='function' AND s.name NOT IN (SELECT DISTINCT caller_name FROM calls)
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [{"name": r[0], "file": r[1]} for r in rows]

    def get_stats(self) -> dict:
        stats = {}
        for table in ["files", "symbols", "calls", "imports", "xrefs", "strings"]:
            row = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            stats[table] = row[0]
        return stats
