"""APK parser using androguard APK + DEX low-level APIs (no AnalyzeAPK, no get_xref_*)."""

from __future__ import annotations

import json
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

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
from ..utils.progress import Progress
from ..db import is_noise_class, truncate_string

# Dalvik invoke-* opcodes
_INVOKE_OPCODES = {
    0x6E: "invoke-virtual",
    0x6F: "invoke-super",
    0x70: "invoke-direct",
    0x71: "invoke-interface",
    0x72: "invoke-virtual/range",
    0x73: "invoke-super/range",
    0x74: "invoke-direct/range",
    0x75: "invoke-interface/range",
}


def parse_apk(
    path: str | Path,
    file_id: Optional[int] = None,
    progress: Optional[Progress] = None,
) -> dict:
    p = Path(path)
    if progress:
        progress.log(f"Parsing APK: {p.name}")

    apk_path = _resolve_apk_path(p)
    if apk_path is None:
        raise ValueError(f"Cannot resolve APK from: {path}")

    symbols: list[Symbol] = []
    calls: list[CallRelation] = []
    imports: list[ImportEntry] = []
    strings: list[StringEntry] = []
    files: list[FileEntry] = []

    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    apk = APK(str(apk_path))

    manifest_info = _parse_manifest(apk, file_id)
    symbols.extend(manifest_info["symbols"])
    files.append(manifest_info["file"])

    # Parse each DEX directly via DEX class
    dex_files = apk.get_all_dex()
    all_classes: set[str] = set()

    for dex_data in dex_files:
        try:
            dex = DEX(dex_data)
            dex_result = _parse_dex(dex, file_id, progress)
            symbols.extend(dex_result["symbols"])
            calls.extend(dex_result["calls"])
            strings.extend(dex_result["strings"])
            all_classes.update(dex_result["classes"])
        except Exception as e:
            if progress:
                progress.error(f"Failed to parse DEX: {e}")

    if progress:
        progress.log(
            f"  Found {len(symbols)} symbols, {len(calls)} calls, "
            f"{len(strings)} strings, {len(all_classes)} classes"
        )

    native_libs = _extract_native_libs(apk, progress)

    return {
        "files": files,
        "symbols": symbols,
        "calls": calls,
        "imports": imports,
        "strings": strings,
        "extra_meta": {
            "package_name": apk.get_package(),
            "app_name": apk.get_app_name(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": apk.get_permissions(),
            "total_classes": len(all_classes),
            "native_libs": native_libs,
        },
    }


def _resolve_apk_path(p: Path) -> Optional[Path]:
    suffix = p.suffix.lower()
    if suffix == ".apk":
        return p
    if suffix == ".xapk":
        return _extract_base_from_xapk(p)
    if suffix in (".apks", ".apkm"):
        return _extract_base_from_bundle(p)
    return p


def _extract_base_from_xapk(xapk_path: Path) -> Optional[Path]:
    tmp_dir = tempfile.mkdtemp(prefix="code-indexer-xapk-")
    try:
        with zipfile.ZipFile(str(xapk_path), "r") as zf:
            if "manifest.json" in zf.namelist():
                manifest = json.loads(zf.read("manifest.json"))
                for name in zf.namelist():
                    if name.endswith(".apk") and name not in manifest.get("split_apks", []):
                        zf.extract(name, tmp_dir)
                        return Path(tmp_dir) / name
            for name in zf.namelist():
                if name.endswith(".apk"):
                    zf.extract(name, tmp_dir)
                    return Path(tmp_dir) / name
    except Exception:
        pass
    return None


def _extract_base_from_bundle(bundle_path: Path) -> Optional[Path]:
    tmp_dir = tempfile.mkdtemp(prefix="code-indexer-bundle-")
    try:
        with zipfile.ZipFile(str(bundle_path), "r") as zf:
            for name in zf.namelist():
                if name.endswith(".apk") and "base" in name.lower():
                    zf.extract(name, tmp_dir)
                    return Path(tmp_dir) / name
            for name in zf.namelist():
                if name.endswith(".apk"):
                    zf.extract(name, tmp_dir)
                    return Path(tmp_dir) / name
    except Exception:
        pass
    return None


def _parse_manifest(apk, file_id: Optional[int]) -> dict:
    symbols = []
    file_entry = FileEntry(path="AndroidManifest.xml", language="XML")

    for activity in apk.get_activities():
        symbols.append(Symbol(
            name=activity.split(".")[-1], full_name=activity,
            type=SymbolType.CLASS, file_id=file_id,
            is_entry_point=True, importance=Importance.HIGH,
            description=f"Activity: {activity}",
        ))
    for service in apk.get_services():
        symbols.append(Symbol(
            name=service.split(".")[-1], full_name=service,
            type=SymbolType.CLASS, file_id=file_id,
            is_entry_point=True, importance=Importance.MEDIUM,
            description=f"Service: {service}",
        ))
    for receiver in apk.get_receivers():
        symbols.append(Symbol(
            name=receiver.split(".")[-1], full_name=receiver,
            type=SymbolType.CLASS, file_id=file_id,
            is_entry_point=True, importance=Importance.MEDIUM,
            description=f"BroadcastReceiver: {receiver}",
        ))
    for provider in apk.get_providers():
        symbols.append(Symbol(
            name=provider.split(".")[-1], full_name=provider,
            type=SymbolType.CLASS, file_id=file_id,
            importance=Importance.MEDIUM,
            description=f"ContentProvider: {provider}",
        ))

    return {"symbols": symbols, "file": file_entry}


def _parse_dex(dex, file_id: Optional[int], progress: Optional[Progress]) -> dict:
    """Parse a DEX file using only DEX low-level API.

    Walks ClassDefItem -> EncodedMethod -> CodeItem -> Dalvik instructions
    to extract classes, methods, fields, and invoke call relationships.
    No AnalyzeAPK, no ClassAnalysis, no get_xref_*.

    Skips framework noise classes (android.*, java.*, kotlin.*, etc.)
    to keep DB size manageable.
    """
    symbols: list[Symbol] = []
    calls: list[CallRelation] = []
    string_entries: list[StringEntry] = []
    classes: set[str] = set()

    method_ids = _build_method_id_table(dex)
    type_ids = _build_type_id_table(dex)

    noise_skipped = 0

    for cls in dex.get_classes():
        class_name = cls.get_name()
        if class_name.startswith("L") and class_name.endswith(";"):
            class_name = class_name[1:-1].replace("/", ".")
        classes.add(class_name)

        # Skip framework noise classes entirely
        if is_noise_class(class_name):
            noise_skipped += 1
            continue

        short_name = class_name.split("$")[-1].split(".")[-1]
        is_entry = _is_android_entry(class_name)

        symbols.append(Symbol(
            name=short_name, full_name=class_name,
            type=SymbolType.CLASS, file_id=file_id,
            importance=Importance.HIGH if is_entry else Importance.MEDIUM,
            is_entry_point=is_entry,
        ))

        # Direct fields
        for field in cls.get_fields():
            field_name = field.get_name()
            symbols.append(Symbol(
                name=field_name, full_name=f"{class_name}.{field_name}",
                type=SymbolType.FIELD, file_id=file_id,
                importance=Importance.LOW,
            ))

        # Direct methods
        for method in cls.get_methods():
            method_name = method.get_name()
            descriptor = method.get_descriptor()
            full_method = f"{class_name}.{method_name}"

            is_entry_m = _is_android_entry_method(method_name, class_name)
            symbols.append(Symbol(
                name=method_name, full_name=full_method,
                type=SymbolType.METHOD, file_id=file_id,
                signature=f"{method_name}{descriptor}",
                importance=_method_importance(method_name, class_name),
                is_entry_point=is_entry_m,
            ))

            # Extract invoke calls from bytecode
            code = method.get_code()
            if code:
                method_calls = _extract_dex_calls_bytecode(
                    code, full_method, method_ids, file_id
                )
                calls.extend(method_calls)

    # Strings from DEX string table
    for s in dex.get_strings():
        if len(s) >= 4:
            string_entries.append(StringEntry(value=truncate_string(s), length=len(s)))

    return {
        "symbols": symbols,
        "calls": calls,
        "imports": [],
        "strings": string_entries,
        "classes": classes,
    }


def _build_method_id_table(dex) -> dict[int, str]:
    """Build method_id index -> 'class.method_name' from DEX header."""
    table = {}
    try:
        # Access the raw DEX structure
        if hasattr(dex, 'header') and hasattr(dex.header, 'method_ids'):
            for i, mid in enumerate(dex.header.method_ids):
                class_name = mid.class_name
                if class_name.startswith("L") and class_name.endswith(";"):
                    class_name = class_name[1:-1].replace("/", ".")
                method_name = mid.method_name
                table[i] = f"{class_name}.{method_name}"
    except Exception:
        pass
    return table


def _build_type_id_table(dex) -> dict[int, str]:
    """Build type_id index -> class name from DEX header."""
    table = {}
    try:
        if hasattr(dex, 'header') and hasattr(dex.header, 'type_ids'):
            for i, tid in enumerate(dex.header.type_ids):
                name = tid
                if isinstance(name, str):
                    if name.startswith("L") and name.endswith(";"):
                        name = name[1:-1].replace("/", ".")
                    table[i] = name
    except Exception:
        pass
    return table


def _extract_dex_calls_bytecode(
    code,
    caller_full_name: str,
    method_ids: dict[int, str],
    file_id: Optional[int],
) -> list[CallRelation]:
    """Extract invoke calls by directly reading Dalvik bytecode operands.

    For invoke-* instructions, the operand is a method_id index into the
    DEX method_id table. We resolve it via our prebuilt table instead of
    parsing instruction.get_output() strings.
    """
    calls: list[CallRelation] = []

    try:
        bytecode = code.get_bc()
        for instruction in bytecode.get_instructions():
            op = instruction.get_op_value()

            if op not in _INVOKE_OPCODES:
                continue

            # Try to resolve via method_id table first (fast path)
            callee_name = None
            call_type = CallType.DIRECT

            if op in (0x6E, 0x72):  # invoke-virtual, invoke-virtual/range
                call_type = CallType.VIRTUAL
            elif op in (0x71, 0x75):  # invoke-interface, invoke-interface/range
                call_type = CallType.VIRTUAL
            elif op == 0x6F:  # invoke-super
                call_type = CallType.DIRECT
            elif op == 0x70:  # invoke-direct
                call_type = CallType.DIRECT

            # Get the method index from the instruction's raw operands
            # invoke-* format: AA|op BBBB  (AA=arg count, BBBB=method_idx)
            # invoke-*/range: op|AA CCCC  (AAAA=arg count, CCCC=method_idx)
            try:
                raw = instruction.get_raw()
                if len(raw) >= 4:
                    # Method index is in bytes 2-3 (little-endian uint16)
                    method_idx = struct.unpack_from('<H', raw, 2)[0]
                    callee_name = method_ids.get(method_idx)
            except Exception:
                pass

            # Fallback: parse from get_output() if table lookup failed
            if not callee_name:
                callee_name = _parse_invoke_output(instruction.get_output())

            if callee_name:
                # Skip calls to noise framework classes
                if is_noise_class(callee_name):
                    continue
                calls.append(CallRelation(
                    caller_name=caller_full_name,
                    callee_name=callee_name,
                    call_type=call_type,
                    file_id=file_id,
                ))
    except Exception:
        pass

    return calls


def _parse_invoke_output(output: str) -> Optional[str]:
    """Fallback: parse invoke instruction output string for callee ref."""
    if not isinstance(output, str) or "->" not in output:
        return None

    try:
        # Format: {regs}, Lclass/name;->methodName(params)returnType
        parts = output.split(",")
        if not parts:
            return None
        ref = parts[-1].strip()
        if "->" not in ref:
            return None

        cls_part, method_part = ref.split("->", 1)
        cls_name = cls_part.strip()
        if cls_name.startswith("L") and cls_name.endswith(";"):
            cls_name = cls_name[1:-1].replace("/", ".")

        paren_idx = method_part.find("(")
        method_name = method_part[:paren_idx] if paren_idx > 0 else method_part

        return f"{cls_name}.{method_name}"
    except Exception:
        return None


def _is_android_entry(class_name: str) -> bool:
    patterns = [
        "Activity", "Service", "Receiver", "Provider",
        "Application", "BroadcastReceiver",
        "ContentProvider", "IntentService",
    ]
    return any(p in class_name for p in patterns)


def _is_android_entry_method(method_name: str, class_name: str) -> bool:
    entry_methods = {
        "onCreate", "onStart", "onResume", "onRestart",
        "onBind", "onReceive", "query", "insert", "update", "delete",
        "JNI_OnLoad",
    }
    if method_name in entry_methods:
        return True
    if method_name == "<init>" and _is_android_entry(class_name):
        return True
    return False


def _method_importance(method_name: str, class_name: str) -> Importance:
    if _is_android_entry_method(method_name, class_name):
        return Importance.HIGH
    if method_name.startswith("on") and method_name[2:3].isupper():
        return Importance.MEDIUM
    if method_name in ("run", "execute", "process", "handle", "doWork"):
        return Importance.MEDIUM
    return Importance.LOW


def _extract_native_libs(apk, progress: Optional[Progress]) -> list[str]:
    native_libs = []
    try:
        for lib in apk.get_files():
            if lib.endswith(".so"):
                native_libs.append(lib)
    except Exception:
        pass
    if progress and native_libs:
        progress.verbose_log(f"  Found {len(native_libs)} native libraries")
    return native_libs