"""Core orchestration: streaming parse -> DB -> analyze -> summary."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .analyzers.arch_detector import detect_architecture
from .analyzers.call_graph import analyze_call_graph
from .analyzers.summary import generate_json_summary, generate_markdown_report, write_outputs
from .db import IndexDatabase, is_noise_class
from .detectors.detector import detect_languages, detect_source_type
from .models import (
    CallRelation,
    FileEntry,
    ImportEntry,
    ProjectMeta,
    SourceType,
    StringEntry,
    Symbol,
    SymbolType,
    Importance,
    XrefEntry,
)
from .parsers.apk_parser import parse_apk
from .parsers.elf_parser import parse_elf
from .parsers.ida_parser import IdaBackend, detect_ida_backend, parse_with_ida
from .parsers.source_parser import parse_source_dir
from .utils.progress import Progress


def index_target(
    path: str,
    output_dir: Optional[str] = None,
    use_ida: bool = False,
    no_ida: bool = False,
    depth: int = 3,
    verbose: bool = False,
) -> Optional[dict]:
    progress = Progress(verbose=verbose)
    target = Path(path).resolve()

    # 1. Detect input type
    try:
        source_type = detect_source_type(target)
    except (FileNotFoundError, ValueError) as e:
        progress.error(str(e))
        return None

    progress.log(f"Detected type: {source_type.value}")

    # 2. Setup output directory
    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = target.parent / f"{target.stem if target.is_file() else target.name}.index"
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / "index.db"

    # 3. Parse and stream into DB
    extra_meta: dict = {}
    tool_used = "unknown"

    # Collect lightweight metadata for summary (not all data, just stats + samples)
    all_files: list[FileEntry] = []
    sample_symbols: list[Symbol] = []  # Keep only non-noise symbols for analysis
    sample_calls: list[CallRelation] = []
    sample_imports: list[ImportEntry] = []

    with IndexDatabase(db_path) as db:
        if source_type == SourceType.SOURCE:
            result = parse_source_dir(target, progress)

            # IDA-NO-MCP export within source dir
            ida_backend = detect_ida_backend(target, use_ida, no_ida, progress)
            ida_symbols, ida_calls, ida_strings = [], [], []
            if ida_backend != IdaBackend.NONE:
                ida_result = parse_with_ida(target, ida_backend, file_id=None, progress=progress)
                ida_symbols = ida_result.get("symbols", [])
                ida_calls = ida_result.get("calls", [])
                ida_strings = ida_result.get("strings", [])
                extra_meta["ida_backend"] = ida_backend

            # Insert files
            file_id_map: dict[str, int] = {}
            for f in result.get("files", []):
                fid = db.insert_file(f)
                file_id_map[f.path] = fid
                f.id = fid
                all_files.append(f)

            # Fix file_ids then stream symbols
            symbols = result.get("symbols", []) + ida_symbols
            for sym in symbols:
                if sym.file_id is None:
                    pass  # will be null
            db.stream_symbols(symbols)

            # Stream calls (resolve IDs after symbols are in)
            calls = result.get("calls", []) + ida_calls
            db.resolve_symbol_ids(calls)
            db.stream_calls(calls)

            # Stream imports
            imports = result.get("imports", [])
            for imp in imports:
                if imp.file_id == 0 or imp.file_id is None:
                    if all_files:
                        imp.file_id = all_files[0].id
            db.stream_imports(imports)

            # Stream strings
            db.stream_strings(result.get("strings", []) + ida_strings)

            # Keep samples for analysis
            sample_symbols = [s for s in symbols if not is_noise_class(s.full_name or "")]
            sample_calls = [c for c in calls if not (is_noise_class(c.caller_name) and is_noise_class(c.callee_name))]
            sample_imports = imports
            extra_meta.update(result.get("extra_meta", {}))

            tool_used = "tree-sitter"
            if ida_backend != IdaBackend.NONE:
                tool_used += f"+{ida_backend}"

        elif source_type == SourceType.SO:
            result = parse_elf(target, progress=progress)

            # IDA for deeper analysis
            ida_backend = detect_ida_backend(target, use_ida, no_ida, progress)
            use_ida_result = False
            ida_symbols, ida_calls, ida_strings = [], [], []
            if ida_backend != IdaBackend.NONE:
                ida_result = parse_with_ida(target, ida_backend, file_id=None, progress=progress)
                if ida_result.get("symbols"):
                    ida_symbols = ida_result["symbols"]
                    ida_calls = ida_result["calls"]
                    ida_strings = ida_result.get("strings", [])
                    use_ida_result = True
                    extra_meta["ida_backend"] = ida_backend

            # Insert file
            file_entry = result["file"]
            file_entry.id = db.insert_file(file_entry)
            all_files.append(file_entry)

            if use_ida_result:
                db.stream_symbols(ida_symbols)
                db.resolve_symbol_ids(ida_calls)
                db.stream_calls(ida_calls)
                db.stream_strings(ida_strings)
                sample_symbols = ida_symbols
                sample_calls = ida_calls
                tool_used = ida_backend
            else:
                symbols = result["symbols"]
                calls = result["calls"]
                db.stream_symbols(symbols)
                db.resolve_symbol_ids(calls)
                db.stream_calls(calls)
                db.stream_imports(result.get("imports", []))
                db.stream_strings(result.get("strings", []))
                sample_symbols = symbols
                sample_calls = calls
                tool_used = "lief"

            sample_imports = result.get("imports", [])
            extra_meta.update(result.get("extra_meta", {}))

        elif source_type == SourceType.APK:
            result = parse_apk(target, progress=progress)

            # Insert files
            for f in result.get("files", []):
                f.id = db.insert_file(f)
                all_files.append(f)

            # Stream symbols, calls, strings directly
            symbols = result.get("symbols", [])
            calls = result.get("calls", [])
            strings = result.get("strings", [])

            db.stream_symbols(symbols)
            db.resolve_symbol_ids(calls)
            db.stream_calls(calls)
            db.stream_strings(strings)

            # Keep non-noise samples for analysis
            sample_symbols = [s for s in symbols if not is_noise_class(s.full_name or "")]
            sample_calls = [c for c in calls if not (is_noise_class(c.caller_name) and is_noise_class(c.callee_name))]
            sample_imports = result.get("imports", [])
            extra_meta.update(result.get("extra_meta", {}))
            tool_used = "androguard"

        else:
            progress.error(f"Unsupported source type: {source_type}")
            return None

        db_stats = db.get_stats()

    progress.log(f"DB stats: {db_stats}")

    # 4. Analyze (using samples, not full data)
    progress.log("Analyzing call graph and architecture...")
    call_graph_result = analyze_call_graph(sample_symbols, sample_calls)

    language_breakdown = None
    if source_type == SourceType.SOURCE:
        language_breakdown = detect_languages(target)

    arch_result = detect_architecture(source_type, all_files, sample_symbols, sample_imports)

    # 5. Create project meta
    meta = ProjectMeta(
        source_path=str(target),
        source_type=source_type,
        scan_time=datetime.now(timezone.utc).isoformat(),
        total_files=db_stats.get("files", 0),
        total_symbols=db_stats.get("symbols", 0),
        total_calls=db_stats.get("calls", 0),
        language_breakdown=language_breakdown,
        tool_used=tool_used,
        extra_meta=extra_meta,
    )

    # 6. Generate summaries
    progress.log("Generating panorama summary...")
    summary = generate_json_summary(
        meta=meta,
        files=all_files,
        symbols=sample_symbols,
        calls=sample_calls,
        imports=sample_imports,
        strings=[],
        call_graph_analysis=call_graph_result,
        arch_analysis=arch_result,
        db_path=str(db_path),
    )

    md_content = generate_markdown_report(summary)
    output_paths = write_outputs(summary, md_content, out_dir)

    # 7. Insert meta into DB
    with IndexDatabase(db_path) as db:
        db.insert_meta(meta)

    progress.log(f"Done in {progress.elapsed()}")

    return {
        "db_path": str(db_path),
        "json_path": output_paths["json_path"],
        "md_path": output_paths["md_path"],
        "summary": summary,
    }
