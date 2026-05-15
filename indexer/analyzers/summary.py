"""Generate JSON and Markdown panorama summaries."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..models import (
    CallRelation,
    FileEntry,
    ImportEntry,
    ProjectMeta,
    SourceType,
    StringEntry,
    Symbol,
    SymbolType,
    XrefEntry,
)


def generate_json_summary(
    meta: ProjectMeta,
    files: list[FileEntry],
    symbols: list[Symbol],
    calls: list[CallRelation],
    imports: list[ImportEntry],
    strings: list[StringEntry],
    call_graph_analysis: dict,
    arch_analysis: dict,
    db_path: str,
) -> dict:
    # Language breakdown
    lang_counts: dict[str, int] = {}
    for f in files:
        if f.language:
            lang_counts[f.language] = lang_counts.get(f.language, 0) + 1
    if meta.language_breakdown:
        lang_counts.update(meta.language_breakdown)

    # Dependencies
    internal_deps: dict[str, list[str]] = {}
    external_deps: dict[str, list[str]] = {}
    for imp in imports:
        if imp.file_id:
            # Find the file path
            f = next((f for f in files if f.id == imp.file_id), None)
            if f:
                key = f.path
                if imp.target.startswith(".") or imp.target.startswith("/"):
                    internal_deps.setdefault(key, []).append(imp.target)
                else:
                    external_deps.setdefault(key, []).append(imp.target)

    # Highlights
    key_structs = [
        {"name": s.name, "fields": 0}
        for s in symbols if s.type == SymbolType.STRUCT
    ][:10]
    key_functions = [
        {"name": s.name, "importance": s.importance.value}
        for s in symbols if s.importance.value == "high" and s.type in (SymbolType.FUNCTION, SymbolType.METHOD)
    ][:20]

    interesting_strings = _find_interesting_strings(strings)

    # Vtable classes (C++ with virtual)
    vtable_classes = list({
        s.name for s in symbols
        if s.type == SymbolType.CLASS and any(
            m.full_name and m.full_name.startswith(s.name) and m.name.startswith("~")
            for m in symbols if m.type == SymbolType.METHOD
        )
    })[:10]

    summary = {
        "version": "1.0",
        "project": {
            "source_path": meta.source_path,
            "source_type": meta.source_type.value,
            "scan_time": meta.scan_time,
            "stats": {
                "total_files": len(files),
                "total_symbols": len(symbols),
                "total_calls": len(calls),
                "total_imports": len(imports),
                "total_strings": len(strings),
            },
            "language_breakdown": lang_counts,
            "tool_used": meta.tool_used,
        },
        "architecture": arch_analysis,
        "call_graph": call_graph_analysis,
        "dependencies": {
            "internal": internal_deps,
            "external": external_deps,
        },
        "highlights": {
            "key_structs": key_structs,
            "key_functions": key_functions,
            "interesting_strings": interesting_strings,
            "vtable_classes": vtable_classes,
        },
        "db_path": db_path,
    }

    return summary


def generate_markdown_report(summary: dict) -> str:
    lines = []
    proj = summary["project"]
    arch = summary["architecture"]
    cg = summary["call_graph"]

    lines.append(f"# Code Panorama: {Path(proj['source_path']).name}")
    lines.append("")

    # Project overview
    lines.append("## Project Overview")
    lines.append(f"- **Path**: `{proj['source_path']}`")
    lines.append(f"- **Type**: {proj['source_type']}")
    lines.append(f"- **Scanned**: {proj['scan_time']}")
    lines.append(f"- **Tool**: {proj.get('tool_used', 'N/A')}")
    lines.append("")

    stats = proj["stats"]
    lines.append("### Stats")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    for k, v in stats.items():
        lines.append(f"| {k} | {v} |")
    lines.append("")

    # Language breakdown
    lang = proj.get("language_breakdown", {})
    if lang:
        lines.append("### Languages")
        for l, c in sorted(lang.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- {l}: {c} files")
        lines.append("")

    # Architecture
    lines.append("## Architecture")
    if arch.get("modules"):
        lines.append(f"**Modules**: {', '.join(arch['modules'][:20])}")
    if arch.get("patterns"):
        lines.append(f"**Patterns**: {', '.join(arch['patterns'])}")
    lines.append("")

    # Entry points
    if arch.get("entry_points"):
        lines.append("### Entry Points")
        for ep in arch["entry_points"]:
            addr = ep.get("address", "")
            file_info = ep.get("file", "")
            extra = f" ({addr})" if addr else f" ({file_info})" if file_info else ""
            lines.append(f"- `{ep['name']}`{extra}")
        lines.append("")

    # Layers
    if arch.get("layers"):
        lines.append("### Layers")
        for layer in arch["layers"]:
            lines.append(f"- **{layer['name']}**: {', '.join(layer.get('files', [])[:5])}")
        lines.append("")

    # Call graph
    lines.append("## Call Graph")
    if cg.get("hot_functions"):
        lines.append("### Hot Functions (most callers)")
        for hf in cg["hot_functions"][:10]:
            lines.append(f"- `{hf['name']}` — {hf['callers']} callers")
        lines.append("")

    if cg.get("entry_chains"):
        lines.append("### Key Call Chains")
        for chain in cg["entry_chains"]:
            lines.append(f"- {' -> '.join(chain['chain'])}")
        lines.append("")

    if cg.get("cycles"):
        lines.append("### Call Cycles")
        for cycle in cg["cycles"][:5]:
            lines.append(f"- {' -> '.join(cycle)}")
        lines.append("")

    # Highlights
    highlights = summary.get("highlights", {})
    if highlights.get("key_functions"):
        lines.append("## Key Functions")
        for kf in highlights["key_functions"][:20]:
            lines.append(f"- `{kf['name']}` ({kf['importance']})")
        lines.append("")

    if highlights.get("interesting_strings"):
        lines.append("## Notable Strings")
        for s in highlights["interesting_strings"][:20]:
            lines.append(f"- `{s}`")
        lines.append("")

    # Database
    lines.append("## Database")
    lines.append(f"SQLite: `{summary['db_path']}`")
    lines.append("")
    lines.append("```sql")
    lines.append("-- Example queries")
    lines.append("SELECT caller_name FROM calls WHERE callee_name = 'target_func';")
    lines.append("SELECT name, type, line FROM symbols WHERE file_id = (SELECT id FROM files WHERE path = 'src/main.c');")
    lines.append("SELECT name, address FROM symbols WHERE is_entry_point = 1;")
    lines.append("```")

    return "\n".join(lines)


def _find_interesting_strings(strings: list[StringEntry]) -> list[str]:
    interesting = []
    keywords = [
        "password", "secret", "key", "token", "api", "url", "host",
        "error", "fail", "debug", "log", "config", "version",
        "encrypt", "decrypt", "cert", "ssl", "crypto",
    ]
    for s in strings:
        val_lower = s.value.lower()
        if any(kw in val_lower for kw in keywords):
            interesting.append(s.value[:100])
            if len(interesting) >= 30:
                break
    return interesting


def write_outputs(
    summary: dict,
    md_content: str,
    output_dir: Path,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "panorama.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    md_path = output_dir / "panorama.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    return {
        "json_path": str(json_path),
        "md_path": str(md_path),
    }
