"""ELF/SO parser using lief and pyelftools."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import lief

from ..models import (
    CallRelation,
    CallType,
    FileEntry,
    ImportEntry,
    StringEntry,
    Symbol,
    SymbolType,
    Importance,
)
from ..db import truncate_string
from ..utils.progress import Progress


def parse_elf(
    path: str | Path,
    file_id: Optional[int] = None,
    progress: Optional[Progress] = None,
) -> dict:
    p = Path(path)
    if progress:
        progress.log(f"Parsing ELF: {p.name}")

    binary = lief.parse(str(p))
    if binary is None:
        raise ValueError(f"lief failed to parse: {path}")

    symbols: list[Symbol] = []
    calls: list[CallRelation] = []
    imports_list: list[ImportEntry] = []
    strings: list[StringEntry] = []

    # File entry
    file_entry = FileEntry(
        path=p.name,
        language="ELF",
        size=p.stat().st_size,
    )

    # Architecture info
    arch = str(binary.header.machine_type) if binary.header else "unknown"
    is_64 = binary.header.identity_class.name == "ELF64" if binary.header else False

    # Exported functions
    exported_names: set[str] = set()
    for sym in binary.exported_functions:
        exported_names.add(sym.name)
        symbols.append(Symbol(
            name=sym.name,
            full_name=sym.name,
            type=SymbolType.FUNCTION,
            file_id=file_id,
            address=hex(sym.value) if sym.value else None,
            is_exported=True,
            importance=Importance.HIGH if _is_entry_like(sym.name) else Importance.MEDIUM,
        ))

    # Exported variables (non-function exported symbols)
    for sym in binary.exported_symbols:
        if sym.type != lief.ELF.Symbol.TYPE.FUNC:
            exported_names.add(sym.name)
            symbols.append(Symbol(
                name=sym.name,
                type=SymbolType.GLOBAL_VAR,
                file_id=file_id,
                address=hex(sym.value) if sym.value else None,
                is_exported=True,
            ))

    # Imported functions
    imported_names: set[str] = set()
    for sym in binary.imported_functions:
        imported_names.add(sym.name)
        symbols.append(Symbol(
            name=sym.name,
            type=SymbolType.FUNCTION,
            file_id=file_id,
            is_imported=True,
            importance=Importance.HIGH,
        ))

    # Imported variables (non-function imported symbols)
    for sym in binary.imported_symbols:
        if sym.type != lief.ELF.Symbol.TYPE.FUNC:
            imported_names.add(sym.name)
            symbols.append(Symbol(
                name=sym.name,
                type=SymbolType.GLOBAL_VAR,
                file_id=file_id,
                is_imported=True,
            ))

    # Internal symbols (not exported/imported)
    for sym in binary.symbols:
        if sym.name and sym.name not in exported_names and sym.name not in imported_names:
            if sym.type == lief.ELF.Symbol.TYPE.FUNC and sym.value != 0:
                symbols.append(Symbol(
                    name=sym.name,
                    type=SymbolType.FUNCTION,
                    file_id=file_id,
                    address=hex(sym.value),
                    importance=Importance.MEDIUM,
                ))
            elif sym.type == lief.ELF.Symbol.TYPE.OBJECT and sym.value != 0:
                symbols.append(Symbol(
                    name=sym.name,
                    type=SymbolType.GLOBAL_VAR,
                    file_id=file_id,
                    address=hex(sym.value),
                ))

    # JNI-style symbols: detect Java native methods
    for sym in symbols:
        if sym.name.startswith("Java_") and sym.type == SymbolType.FUNCTION:
            sym.importance = Importance.HIGH
            sym.is_entry_point = True
            java_name = sym.name.replace("Java_", "").replace("_", ".")
            sym.description = f"JNI native: {java_name}"

    # Relocations -> call relationships
    for rel in binary.relocations:
        if rel.symbol and rel.symbol.name:
            callee = rel.symbol.name
            # Find callers by section analysis (simplified: record the relocation target)
            if callee in imported_names:
                pass  # Will be linked via call graph later

    # Strings from .rodata and other sections
    for section in binary.sections:
        if section.name in (".rodata", ".data", ".dynstr"):
            try:
                data = bytes(section.content)
                _extract_strings(data, strings, section.virtual_address)
            except Exception:
                pass

    # DWARF debug info (if available)
    dwarf_info = _parse_dwarf(p) if _has_dwarf(binary) else None
    if dwarf_info:
        if progress:
            progress.log(f"  Found DWARF debug info, enriching symbols...")
        _enrich_from_dwarf(symbols, dwarf_info, file_id)

    # Build call relationships from relocations
    for rel in binary.relocations:
        if rel.symbol and rel.symbol.name:
            callee_name = rel.symbol.name
            if callee_name in imported_names:
                # The relocation is in some function that calls this import
                # lief gives us the address where the call is patched
                pass

    # Try to build calls from PLT/GOT
    pltgot_calls = _extract_pltgot_calls(binary, symbols, file_id)
    calls.extend(pltgot_calls)

    if progress:
        progress.log(
            f"  Found {len(symbols)} symbols, {len(calls)} calls, {len(strings)} strings"
        )

    return {
        "file": file_entry,
        "symbols": symbols,
        "calls": calls,
        "imports": imports_list,
        "strings": strings,
        "extra_meta": {
            "arch": arch,
            "is_64bit": is_64,
            "exported_count": len(exported_names),
            "imported_count": len(imported_names),
        },
    }


def _is_entry_like(name: str) -> bool:
    entry_patterns = [
        "main", "JNI_OnLoad", "_start", "init", "entry",
        "onCreate", "onStart", "onResume",
    ]
    name_lower = name.lower()
    return any(p in name_lower for p in entry_patterns)


def _extract_strings(data: bytes, strings: list[StringEntry], base_addr: int = 0, min_len: int = 4):
    current = bytearray()
    start_offset = 0

    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not current:
                start_offset = i
            current.append(b)
        else:
            if len(current) >= min_len:
                try:
                    value = current.decode("utf-8", errors="replace")
                    addr = hex(base_addr + start_offset) if base_addr else None
                    strings.append(StringEntry(
                        address=addr,
                        value=truncate_string(value),
                        length=len(current),
                    ))
                except Exception:
                    pass
            current = bytearray()

    if len(current) >= min_len:
        try:
            value = current.decode("utf-8", errors="replace")
            addr = hex(base_addr + start_offset) if base_addr else None
            strings.append(StringEntry(address=addr, value=truncate_string(value), length=len(current)))
        except Exception:
            pass


def _has_dwarf(binary: lief.ELF.Binary) -> bool:
    for section in binary.sections:
        if section.name.startswith(".debug_"):
            return True
    return False


def _parse_dwarf(path: Path) -> Optional[dict]:
    try:
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as f:
            elffile = ELFFile(f)
            if not elffile.has_dwarf_info():
                return None

            dwarf = elffile.get_dwarf_info()
            cu_info: list[dict] = []

            for cu in dwarf.iter_CUs():
                top_die = cu.get_top_DIE()
                comp_dir = top_die.attributes.get("DW_AT_comp_dir")
                name = top_die.attributes.get("DW_AT_name")
                cu_info.append({
                    "comp_dir": comp_dir.value.decode() if comp_dir else None,
                    "name": name.value.decode() if name else None,
                    "functions": _extract_dwarf_functions(cu, dwarf),
                })

            return {"compile_units": cu_info}
    except ImportError:
        return None
    except Exception:
        return None


def _extract_dwarf_functions(cu, dwarf) -> list[dict]:
    funcs = []
    try:
        for die in cu.iter_DIEs():
            if die.tag == "DW_TAG_subprogram":
                name_attr = die.attributes.get("DW_AT_name")
                low_pc = die.attributes.get("DW_AT_low_pc")
                if name_attr:
                    funcs.append({
                        "name": name_attr.value.decode() if isinstance(name_attr.value, bytes) else str(name_attr.value),
                        "address": hex(low_pc.value) if low_pc else None,
                    })
    except Exception:
        pass
    return funcs


def _enrich_from_dwarf(symbols: list[Symbol], dwarf_info: dict, file_id: Optional[int]):
    dwarf_funcs: dict[str, dict] = {}
    for cu in dwarf_info.get("compile_units", []):
        for func in cu.get("functions", []):
            if func.get("address"):
                dwarf_funcs[func["address"]] = func
            if func.get("name"):
                dwarf_funcs[func["name"]] = func

    for sym in symbols:
        if sym.address and sym.address in dwarf_funcs:
            info = dwarf_funcs[sym.address]
            if info.get("name") and not sym.name.startswith("sub_"):
                pass  # Keep existing name
        elif sym.name in dwarf_funcs:
            info = dwarf_funcs[sym.name]
            if info.get("address") and not sym.address:
                sym.address = info["address"]


def _extract_pltgot_calls(
    binary: lief.ELF.Binary,
    symbols: list[Symbol],
    file_id: Optional[int],
) -> list[CallRelation]:
    calls = []

    # Get imported function names
    imported_func_names = {sym.name for sym in binary.imported_functions}

    # Get internal function names with addresses
    internal_funcs: dict[str, str] = {}
    for sym in symbols:
        if sym.type == SymbolType.FUNCTION and sym.address and not sym.is_imported:
            internal_funcs[sym.name] = sym.address

    # From relocations, we can infer which internal functions call imports
    # This is a simplified approach - full call graph requires disassembly
    for rel in binary.relocations:
        if rel.symbol and rel.symbol.name in imported_func_names:
            # The relocation address falls within some function's range
            rel_addr = rel.address
            if rel_addr:
                caller = _find_function_at(internal_funcs, rel_addr)
                if caller:
                    calls.append(CallRelation(
                        caller_name=caller,
                        callee_name=rel.symbol.name,
                        caller_id=None,
                        callee_id=None,
                        call_type=CallType.DIRECT,
                        file_id=file_id,
                        address=hex(rel_addr),
                    ))

    return calls


def _find_function_at(func_map: dict[str, str], addr: int) -> Optional[str]:
    best_name = None
    best_addr = 0

    for name, addr_str in func_map.items():
        try:
            func_addr = int(addr_str, 16)
        except ValueError:
            continue
        if func_addr <= addr and func_addr > best_addr:
            best_name = name
            best_addr = func_addr

    return best_name
