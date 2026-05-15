"""Architecture and pattern detection for source code projects."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..models import FileEntry, ImportEntry, Symbol, SymbolType, SourceType


def detect_architecture(
    source_type: SourceType,
    files: list[FileEntry],
    symbols: list[Symbol],
    imports: list[ImportEntry],
) -> dict:
    if source_type == SourceType.SOURCE:
        return _detect_source_arch(files, symbols, imports)
    elif source_type == SourceType.SO:
        return _detect_so_arch(symbols)
    elif source_type == SourceType.APK:
        return _detect_apk_arch(symbols)
    return {"modules": [], "entry_points": [], "layers": [], "patterns": []}


def _detect_source_arch(
    files: list[FileEntry],
    symbols: list[Symbol],
    imports: list[ImportEntry],
) -> dict:
    # Detect modules from directory structure
    modules = _detect_modules(files)

    # Detect entry points
    entry_points = [
        {"name": s.name, "file": s.full_name or s.name}
        for s in symbols if s.is_entry_point
    ]

    # Detect layers from directory names
    layers = _detect_layers(files)

    # Detect patterns
    patterns = _detect_patterns(symbols, imports)

    return {
        "modules": modules,
        "entry_points": entry_points,
        "layers": layers,
        "patterns": patterns,
    }


def _detect_so_arch(symbols: list[Symbol]) -> dict:
    jni_methods = [s for s in symbols if s.name.startswith("Java_")]
    exports = [s for s in symbols if s.is_exported]
    entry_points = [s for s in symbols if s.is_entry_point]

    modules = []
    if jni_methods:
        jni_packages = set()
        for m in jni_methods:
            parts = m.name.replace("Java_", "").split("_")
            if len(parts) > 1:
                jni_packages.add(parts[0])
        modules = list(jni_packages)

    return {
        "modules": modules,
        "entry_points": [
            {"name": s.name, "address": s.address}
            for s in entry_points
        ],
        "layers": [],
        "patterns": ["JNI Native Library"] if jni_methods else ["Shared Library"],
    }


def _detect_apk_arch(symbols: list[Symbol]) -> dict:
    activities = [s for s in symbols if s.description and "Activity" in s.description]
    services = [s for s in symbols if s.description and "Service" in s.description]
    receivers = [s for s in symbols if s.description and "Receiver" in s.description]
    providers = [s for s in symbols if s.description and "Provider" in s.description]

    # Detect packages from class names
    packages = set()
    for s in symbols:
        if s.full_name and "." in s.full_name:
            parts = s.full_name.rsplit(".", 1)[0]
            # Take top-level package
            top = parts.split(".")[0] if parts else parts
            packages.add(top)

    entry_points = [
        {"name": s.name, "type": s.description or "Component"}
        for s in (activities + services + receivers + providers)
        if s.is_entry_point
    ]

    patterns = []
    if activities and services:
        patterns.append("Android App (Activity + Service)")
    elif activities:
        patterns.append("Android Activity App")

    return {
        "modules": sorted(packages)[:20],
        "entry_points": entry_points[:20],
        "layers": [
            {"name": "UI Layer", "files": [s.name for s in activities[:5]]},
            {"name": "Service Layer", "files": [s.name for s in services[:5]]},
        ],
        "patterns": patterns,
    }


def _detect_modules(files: list[FileEntry]) -> list[str]:
    dirs: dict[str, int] = {}
    for f in files:
        if f.module:
            dirs[f.module] = dirs.get(f.module, 0) + 1
    return sorted(dirs.keys(), key=lambda d: dirs[d], reverse=True)[:20]


def _detect_layers(files: list[FileEntry]) -> list[dict]:
    layer_keywords = {
        "ui": ["ui", "view", "activity", "fragment", "controller", "page", "screen"],
        "api": ["api", "handler", "controller", "route", "endpoint", "servlet"],
        "service": ["service", "manager", "processor", "engine", "core"],
        "data": ["data", "repository", "dao", "model", "entity", "dto"],
        "net": ["net", "network", "http", "client", "request", "socket"],
        "crypto": ["crypto", "cipher", "encrypt", "decrypt", "ssl", "tls"],
        "util": ["util", "helper", "common", "base", "tool", "misc"],
    }

    layers = []
    for layer_name, keywords in layer_keywords.items():
        matching = [
            f.path for f in files
            if any(kw in f.path.lower() for kw in keywords)
        ]
        if matching:
            layers.append({"name": f"{layer_name.title()} Layer", "files": matching[:10]})

    return layers


def _detect_patterns(symbols: list[Symbol], imports: list[ImportEntry]) -> list[str]:
    patterns = []
    sym_names = {s.name.lower() for s in symbols}
    import_targets = {i.target.lower() for i in imports}

    # Singleton
    if "getinstance" in sym_names or "shared" in sym_names:
        patterns.append("Singleton")

    # Observer/Callback
    if "observer" in sym_names or "listener" in sym_names or "callback" in sym_names:
        patterns.append("Observer/Callback")

    # Factory
    if "factory" in sym_names or "create" in sym_names:
        patterns.append("Factory")

    # MVC/MVP/MVVM
    has_model = any("model" in n for n in sym_names)
    has_view = any("view" in n for n in sym_names)
    has_presenter = any("presenter" in n for n in sym_names)
    has_viewmodel = any("viewmodel" in n for n in sym_names)

    if has_model and has_view and has_presenter:
        patterns.append("MVP")
    elif has_model and has_view and has_viewmodel:
        patterns.append("MVVM")
    elif has_model and has_view:
        patterns.append("MVC")

    # JNI
    if any(s.name.startswith("Java_") for s in symbols):
        patterns.append("JNI Native Bridge")

    # Event-driven
    if "event" in sym_names or "dispatch" in sym_names:
        patterns.append("Event-driven")

    if not patterns:
        patterns.append("Standard")

    return patterns
