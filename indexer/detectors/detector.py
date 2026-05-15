"""Detect input type: source directory, .so file, or .apk file."""

from __future__ import annotations

from pathlib import Path

from ..models import SourceType

SO_EXTENSIONS = {".so", ".o", ".a", ".ko"}
APK_EXTENSIONS = {".apk", ".apks", ".xapk", ".apkm"}
SOURCE_EXTENSIONS = {
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".c++", ".h++",
    ".java", ".kt", ".scala",
    ".smali", ".j",
    ".py", ".rs", ".go", ".cs",
    ".s", ".asm", ".S",
}

MAX_BINARY_SIZE = 500 * 1024 * 1024  # 500MB


def detect_source_type(path: str | Path) -> SourceType:
    p = Path(path)

    if not p.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    suffix = p.suffix.lower()

    if suffix in APK_EXTENSIONS:
        return SourceType.APK

    if suffix in SO_EXTENSIONS:
        return SourceType.SO

    if p.is_file():
        if suffix in {".dex"}:
            return SourceType.APK
        if _is_elf(p):
            return SourceType.SO
        raise ValueError(
            f"Unsupported file type: {suffix}. "
            f"Supported: directories, .so/.o/.a, .apk/.apks/.xapk/.apkm"
        )

    if p.is_dir():
        has_source = any(
            f.suffix.lower() in SOURCE_EXTENSIONS
            for f in p.rglob("*")
            if f.is_file()
        )
        has_binary = any(
            f.suffix.lower() in SO_EXTENSIONS or (f.is_file() and _is_elf_fast(f))
            for f in p.rglob("*")
            if f.is_file()
        )
        if has_source or has_binary:
            return SourceType.SOURCE
        raise ValueError(f"No recognizable source or binary files found in: {path}")

    raise ValueError(f"Cannot determine type of: {path}")


def _is_elf(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except (OSError, IOError):
        return False


def _is_elf_fast(p: Path) -> bool:
    if p.stat().st_size < 16:
        return False
    return _is_elf(p)


def detect_languages(path: Path) -> dict[str, int]:
    lang_map = {
        ".c": "C", ".h": "C",
        ".cpp": "C++", ".hpp": "C++", ".cc": "C++", ".cxx": "C++",
        ".java": "Java",
        ".kt": "Kotlin",
        ".smali": "Smali",
        ".py": "Python",
        ".rs": "Rust",
        ".go": "Go",
        ".cs": "C#",
        ".s": "ASM", ".S": "ASM", ".asm": "ASM",
    }
    counts: dict[str, int] = {}
    for f in path.rglob("*"):
        if not f.is_file():
            continue
        lang = lang_map.get(f.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    return counts
