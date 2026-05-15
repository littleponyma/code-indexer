"""IDA Pro integration: idalib open -> exec INP.py -> parse exported files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..models import (
    CallRelation,
    CallType,
    Symbol,
    SymbolType,
    StringEntry,
    Importance,
)
from ..utils.progress import Progress


class IdaBackend:
    IDALIB = "idalib"
    NO_MCP = "ida-no-mcp"
    NONE = "none"


def detect_ida_backend(
    path: str | Path,
    force_ida: bool = False,
    no_ida: bool = False,
    progress: Optional[Progress] = None,
) -> str:
    if no_ida:
        return IdaBackend.NONE

    p = Path(path)

    # Check for pre-exported IDA-NO-MCP data
    if (p / "decompile").is_dir() and list((p / "decompile").glob("*.c")):
        if progress:
            progress.log("  IDA-NO-MCP export data detected")
        return IdaBackend.NO_MCP

    # Check idalib
    try:
        import idapro
        idapro.get_library_version()
        if progress:
            progress.log("  idalib + INP.py available")
        return IdaBackend.IDALIB
    except Exception:
        pass

    return IdaBackend.NONE


def parse_with_ida(
    path: str | Path,
    backend: str,
    file_id: Optional[int] = None,
    progress: Optional[Progress] = None,
) -> dict:
    if backend == IdaBackend.IDALIB:
        return _parse_idalib(path, file_id, progress)
    elif backend == IdaBackend.NO_MCP:
        return _parse_export_dir(path, file_id, progress)
    return _empty_result()


def _empty_result() -> dict:
    return {"files": [], "symbols": [], "calls": [], "imports": [], "strings": [], "xrefs": []}


# --- idalib: open -> exec INP.py -> close -> parse exported files ---

_INP_PATHS = [
    # Skill directory (shipped with code-indexer)
    Path(__file__).parent.parent.parent / ".claude" / "skills" / "code-indexer" / "INP.py",
    # Global skill directory
    Path.home() / ".claude" / "skills" / "code-indexer" / "INP.py",
    # IDA plugins directory
    Path.home() / "AppData" / "Roaming" / "Hex-Rays" / "IDA Pro" / "plugins" / "INP.py",
]


def _find_inp() -> Optional[Path]:
    for p in _INP_PATHS:
        if p.exists():
            return p
    return None


def _parse_idalib(
    path: str | Path,
    file_id: Optional[int],
    progress: Optional[Progress],
) -> dict:
    if progress:
        progress.log(f"  idalib: opening {path}")

    import idapro
    from ..db import truncate_string

    p = Path(path)
    inp = _find_inp()

    if inp is None:
        if progress:
            progress.error("  INP.py not found, cannot export")
        return _empty_result()

    if progress:
        progress.log(f"  Running INP.py: {inp}")

    export_dir = None

    try:
        idapro.open_database(str(p), True)

        try:
            # Initialize Hex-Rays decompiler for idalib headless mode
            try:
                import ida_hexrays
                if ida_hexrays and ida_hexrays.init_hexrays_plugin():
                    if progress:
                        progress.log("  Hex-Rays decompiler initialized")
                else:
                    if progress:
                        progress.log("  Hex-Rays not available, will use disassembly fallback")
            except Exception:
                if progress:
                    progress.log("  Hex-Rays not available, will use disassembly fallback")

            import ida_nalt
            input_path = ida_nalt.get_input_file_path()
            if input_path:
                export_dir = str(Path(input_path).parent / f"{Path(input_path).name}_export_for_ai")
            else:
                export_dir = str(p.parent / f"{p.name}_export_for_ai")

            # exec INP.py script, then call do_export_sync
            inp_globals = {"__name__": "INP", "__builtins__": __builtins__}
            exec(inp.read_text(encoding="utf-8"), inp_globals)
            inp_globals["do_export_sync"](export_dir=export_dir, skip_auto_analysis=True)

        finally:
            idapro.close_database(0)

    except Exception as e:
        if progress:
            progress.error(f"  idalib error: {e}")
        try:
            idapro.close_database(0)
        except Exception:
            pass
        return _empty_result()

    if progress:
        progress.log(f"  INP.py export done: {export_dir}")

    # Parse exported files (after DB closed)
    return _parse_export_dir(export_dir, file_id, progress)


# --- Parse IDA-NO-MCP exported directory ---

FUNC_HEADER_RE = re.compile(
    r'/\*\s*\n\s*\*\s*func-name:\s*(\S+)\s*\n\s*\*\s*func-address:\s*(0x[0-9a-fA-F]+)\s*\n'
    r'(?:\s*\*\s*export-type:\s*(\S+)\s*\n)?'
    r'(?:\s*\*\s*callers:\s*(.*?)\s*\n)?'
    r'(?:\s*\*\s*callees:\s*(.*?)\s*\n)?'
    r'(?:\s*\*\s*fallback-reason:\s*(.*?)\s*\n)?'
    r'\s*\*/',
    re.MULTILINE,
)


def _parse_export_dir(
    path: str | Path,
    file_id: Optional[int],
    progress: Optional[Progress],
) -> dict:
    from ..db import truncate_string

    p = Path(path)
    decompile_dir = p / "decompile"
    disassembly_dir = p / "disassembly"

    if not decompile_dir.is_dir() and not disassembly_dir.is_dir():
        if progress:
            progress.error(f"  No decompile/ or disassembly/ in {path}")
        return _empty_result()

    if progress:
        progress.log(f"  Parsing IDA export: {path}")

    symbols: list[Symbol] = []
    calls: list[CallRelation] = []
    strings: list[StringEntry] = []

    # Parse .c and .asm files
    c_files = sorted(decompile_dir.glob("*.c")) if decompile_dir.is_dir() else []
    asm_files = sorted(disassembly_dir.glob("*.asm")) if disassembly_dir.is_dir() else []

    for f in c_files + asm_files:
        content = f.read_text(encoding="utf-8", errors="replace")
        m = FUNC_HEADER_RE.search(content)
        if not m:
            continue

        func_name = m.group(1)
        func_addr = m.group(2)
        callers_str = m.group(4)
        callees_str = m.group(5)

        is_entry = func_name in ("main", "start", "_start", "JNI_OnLoad")
        is_jni = func_name.startswith("Java_")

        sym = Symbol(
            name=func_name, type=SymbolType.FUNCTION, file_id=file_id,
            address=func_addr,
            is_entry_point=is_entry or is_jni,
            importance=Importance.HIGH if (is_entry or is_jni) else Importance.MEDIUM,
        )
        if is_jni:
            sym.description = f"JNI native: {func_name.replace('Java_', '').replace('_', '.')}"
        symbols.append(sym)

        # Callees
        if callees_str and callees_str != "none":
            for addr in callees_str.split(","):
                addr = addr.strip()
                if addr.startswith("0x"):
                    calls.append(CallRelation(
                        caller_name=func_name, callee_name=addr,
                        address=addr, call_type=CallType.DIRECT, file_id=file_id,
                    ))

        # Callers
        if callers_str and callers_str != "none":
            for addr in callers_str.split(","):
                addr = addr.strip()
                if addr.startswith("0x"):
                    calls.append(CallRelation(
                        caller_name=addr, callee_name=func_name,
                        address=addr, call_type=CallType.DIRECT, file_id=file_id,
                    ))

    # imports.txt
    imp_file = p / "imports.txt"
    if imp_file.exists():
        for line in imp_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            addr, name = line.split(":", 1)
            symbols.append(Symbol(
                name=name.strip(), type=SymbolType.FUNCTION, file_id=file_id,
                address=addr.strip(), is_imported=True, importance=Importance.HIGH,
            ))

    # exports.txt
    exp_file = p / "exports.txt"
    if exp_file.exists():
        for line in exp_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            addr, name = line.split(":", 1)
            is_entry = name.strip() in ("main", "start", "_start", "JNI_OnLoad")
            symbols.append(Symbol(
                name=name.strip(), type=SymbolType.FUNCTION, file_id=file_id,
                address=addr.strip(), is_exported=True,
                is_entry_point=is_entry, importance=Importance.HIGH,
            ))

    # strings.txt
    str_file = p / "strings.txt"
    if str_file.exists():
        for line in str_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(" | ", 3)
            if len(parts) >= 4:
                strings.append(StringEntry(
                    address=parts[0].strip(), value=truncate_string(parts[3].strip()),
                    length=int(parts[1]) if parts[1].strip().isdigit() else None,
                ))

    # Resolve callee/caller addresses to names
    addr_to_name = {}
    for sym in symbols:
        if sym.address:
            addr_to_name[sym.address] = sym.name
    for call in calls:
        if call.caller_name.startswith("0x") and call.caller_name in addr_to_name:
            call.caller_name = addr_to_name[call.caller_name]
        if call.callee_name.startswith("0x") and call.callee_name in addr_to_name:
            call.callee_name = addr_to_name[call.callee_name]

    if progress:
        progress.log(f"    {len(symbols)} symbols, {len(calls)} calls from {len(c_files)}+{len(asm_files)} files")

    return {"files": [], "symbols": symbols, "calls": calls, "imports": [], "strings": strings, "xrefs": []}