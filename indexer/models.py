"""Data models for the code indexer."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class SourceType(enum.Enum):
    SOURCE = "source"
    SO = "so"
    APK = "apk"


class SymbolType(enum.Enum):
    FUNCTION = "function"
    CLASS = "class"
    STRUCT = "struct"
    METHOD = "method"
    FIELD = "field"
    GLOBAL_VAR = "global_var"
    ENUM = "enum"
    INTERFACE = "interface"
    NAMESPACE = "namespace"


class CallType(enum.Enum):
    DIRECT = "direct"
    VIRTUAL = "virtual"
    CALLBACK = "callback"
    INDIRECT = "indirect"


class Importance(enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class FileEntry:
    path: str
    language: Optional[str] = None
    size: int = 0
    symbol_count: int = 0
    is_entry_point: bool = False
    module: Optional[str] = None
    id: Optional[int] = None


@dataclass
class Symbol:
    name: str
    type: SymbolType
    full_name: Optional[str] = None
    file_id: Optional[int] = None
    address: Optional[str] = None
    line: Optional[int] = None
    end_line: Optional[int] = None
    signature: Optional[str] = None
    is_exported: bool = False
    is_imported: bool = False
    is_entry_point: bool = False
    importance: Importance = Importance.MEDIUM
    description: Optional[str] = None
    module: Optional[str] = None
    extra: Optional[dict] = None
    id: Optional[int] = None


@dataclass
class CallRelation:
    caller_name: str
    callee_name: str
    caller_id: Optional[int] = None
    callee_id: Optional[int] = None
    call_type: CallType = CallType.DIRECT
    file_id: Optional[int] = None
    line: Optional[int] = None
    address: Optional[str] = None
    id: Optional[int] = None


@dataclass
class ImportEntry:
    file_id: int
    target: str
    import_type: Optional[str] = None
    line: Optional[int] = None
    id: Optional[int] = None


@dataclass
class XrefEntry:
    from_symbol_id: int
    to_symbol_id: int
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    xref_type: Optional[str] = None
    id: Optional[int] = None


@dataclass
class StringEntry:
    value: str
    address: Optional[str] = None
    encoding: str = "utf-8"
    length: Optional[int] = None
    referenced_by: Optional[int] = None
    id: Optional[int] = None


@dataclass
class ProjectMeta:
    source_path: str
    source_type: SourceType
    scan_time: str
    total_files: int = 0
    total_symbols: int = 0
    total_calls: int = 0
    language_breakdown: Optional[dict] = None
    tool_used: Optional[str] = None
    extra_meta: Optional[dict] = None
    id: Optional[int] = None


@dataclass
class IndexResult:
    meta: ProjectMeta
    files: list[FileEntry] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    calls: list[CallRelation] = field(default_factory=list)
    imports: list[ImportEntry] = field(default_factory=list)
    xrefs: list[XrefEntry] = field(default_factory=list)
    strings: list[StringEntry] = field(default_factory=list)
