"""Source code parser using tree-sitter and regex fallbacks."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
import tree_sitter_java as tsjava
from tree_sitter import Language, Parser, Node

from ..models import (
    CallRelation,
    CallType,
    FileEntry,
    ImportEntry,
    Symbol,
    SymbolType,
    Importance,
)
from ..utils.progress import Progress

LANGUAGE_MAP = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".h++": "cpp",
    ".java": "java",
    ".py": None,  # Python not supported by tree-sitter in this version, skip
}

LANG_DISPLAY = {
    "c": "C", "cpp": "C++", "java": "Java", "smali": "Smali",
}

# Tree-sitter language objects
_TS_LANGUAGES = {
    "c": Language(tsc.language()),
    "cpp": Language(tscpp.language()),
    "java": Language(tsjava.language()),
}

_SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__",
    ".idea", ".vs", "build", "out", "dist", ".gradle",
    "CMakeFiles", "CMakeScripts", ".cache",
}


def parse_source_dir(
    path: str | Path,
    progress: Optional[Progress] = None,
) -> dict:
    p = Path(path)
    if progress:
        progress.log(f"Parsing source directory: {p}")

    all_files: list[FileEntry] = []
    all_symbols: list[Symbol] = []
    all_calls: list[CallRelation] = []
    all_imports: list[ImportEntry] = []

    # Collect files
    source_files = _collect_source_files(p)
    if progress:
        progress.log(f"  Found {len(source_files)} source files")

    # Parse each file
    parsers = _init_parsers()
    for i, sf in enumerate(source_files):
        if progress and (i + 1) % 50 == 0:
            progress.verbose_log(f"  Parsing file {i + 1}/{len(source_files)}")

        lang = LANGUAGE_MAP.get(sf.suffix.lower())
        if lang and lang in parsers:
            result = _parse_with_treesitter(sf, p, parsers[lang], lang)
        elif sf.suffix.lower() == ".smali":
            result = _parse_smali(sf, p)
        else:
            continue

        all_files.append(result["file"])
        all_symbols.extend(result["symbols"])
        all_calls.extend(result["calls"])
        all_imports.extend(result["imports"])

    # Update symbol_count on files
    file_sym_counts: dict[str, int] = {}
    for sym in all_symbols:
        if sym.file_id:
            file_sym_counts[sym.file_id] = file_sym_counts.get(sym.file_id, 0) + 1

    if progress:
        progress.log(
            f"  Parsed {len(all_files)} files, {len(all_symbols)} symbols, "
            f"{len(all_calls)} calls"
        )

    return {
        "files": all_files,
        "symbols": all_symbols,
        "calls": all_calls,
        "imports": all_imports,
        "strings": [],
    }


def _collect_source_files(root: Path) -> list[Path]:
    files = []
    extensions = set(LANGUAGE_MAP.keys()) | {".smali"}
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        # Skip hidden and build dirs
        if any(part.startswith(".") or part in _SKIP_DIRS for part in f.relative_to(root).parts):
            continue
        if f.suffix.lower() in extensions:
            files.append(f)
    return files


def _init_parsers() -> dict[str, Parser]:
    parsers = {}
    for lang_name, language in _TS_LANGUAGES.items():
        parser = Parser(language)
        parsers[lang_name] = parser
    return parsers


def _parse_with_treesitter(
    file_path: Path,
    root: Path,
    parser: Parser,
    lang: str,
) -> dict:
    rel_path = str(file_path.relative_to(root)).replace("\\", "/")

    try:
        source = file_path.read_bytes()
    except (OSError, UnicodeDecodeError):
        return {"file": FileEntry(path=rel_path, language=LANG_DISPLAY.get(lang, lang)), "symbols": [], "calls": [], "imports": []}

    tree = parser.parse(source)

    file_entry = FileEntry(
        path=rel_path,
        language=LANG_DISPLAY.get(lang, lang),
        size=len(source),
        module=_detect_module(rel_path),
    )

    symbols: list[Symbol] = []
    calls: list[CallRelation] = []
    imports: list[ImportEntry] = []

    visitor = _TreeSitterVisitor(rel_path, lang)
    visitor.visit(tree.root_node)

    symbols = visitor.symbols
    calls = visitor.calls
    imports = visitor.imports

    return {"file": file_entry, "symbols": symbols, "calls": calls, "imports": imports}


class _TreeSitterVisitor:
    def __init__(self, file_path: str, lang: str):
        self.file_path = file_path
        self.lang = lang
        self.symbols: list[Symbol] = []
        self.calls: list[CallRelation] = []
        self.imports: list[ImportEntry] = []
        self._current_class: Optional[str] = None

    def visit(self, node: Node):
        method = getattr(self, f"_visit_{node.type}", None)
        if method:
            method(node)
        else:
            for child in node.children:
                self.visit(child)

    # --- C/C++ ---

    def _visit_function_definition(self, node: Node):
        name = self._get_func_name(node)
        if not name:
            return

        full_name = f"{self._current_class}::{name}" if self._current_class else name
        is_entry = name in ("main", "WinMain", "JNI_OnLoad", "_start")

        self.symbols.append(Symbol(
            name=name,
            full_name=full_name,
            type=SymbolType.FUNCTION,
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            is_entry_point=is_entry,
            importance=Importance.HIGH if is_entry else Importance.MEDIUM,
            module=_detect_module(self.file_path),
        ))

        # Extract calls within function
        self._extract_calls_from_node(node, full_name or name)

        for child in node.children:
            if child.type not in ("compound_statement", "body"):
                continue
            for stmt in child.children:
                self.visit(stmt)

    def _visit_declaration(self, node: Node):
        # struct/enum/class declarations
        for child in node.children:
            if child.type == "struct_specifier":
                self._visit_struct_specifier(child)
            elif child.type == "enum_specifier":
                self._visit_enum_specifier(child)
            elif child.type == "class_specifier":
                self._visit_class_specifier(child)

    def _visit_struct_specifier(self, node: Node):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()
            # Skip if this struct is only referenced (no body = forward declaration or type reference)
            has_body = any(c.type == "field_declaration_list" for c in node.children)
            if not has_body:
                return
            # Skip duplicates within same file
            if any(s.name == name and s.type == SymbolType.STRUCT for s in self.symbols):
                return
            self.symbols.append(Symbol(
                name=name,
                type=SymbolType.STRUCT,
                line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                module=_detect_module(self.file_path),
            ))

    def _visit_enum_specifier(self, node: Node):
        name_node = node.child_by_field_name("name")
        if name_node:
            self.symbols.append(Symbol(
                name=name_node.text.decode(),
                type=SymbolType.ENUM,
                line=node.start_point[0] + 1,
                module=_detect_module(self.file_path),
            ))

    # --- C++ class ---

    def _visit_class_specifier(self, node: Node):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()
            self._current_class = name
            self.symbols.append(Symbol(
                name=name,
                type=SymbolType.CLASS,
                line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                module=_detect_module(self.file_path),
            ))

    # --- Java ---

    def _visit_class_declaration(self, node: Node):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = name_node.text.decode()
            prev_class = self._current_class
            self._current_class = name

            is_entry = any(
                base.text.decode() in ("Activity", "Service", "Application")
                for base in node.children_by_field_name("interfaces")
            ) if hasattr(node, "children_by_field_name") else False

            self.symbols.append(Symbol(
                name=name,
                full_name=name,
                type=SymbolType.CLASS,
                line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                is_entry_point=is_entry,
                importance=Importance.HIGH if is_entry else Importance.MEDIUM,
                module=_detect_module(self.file_path),
            ))

            for child in node.children:
                self.visit(child)

            self._current_class = prev_class

    def _visit_method_declaration(self, node: Node):
        name_node = node.child_by_field_name("name")
        if not name_node:
            return

        name = name_node.text.decode()
        full_name = f"{self._current_class}.{name}" if self._current_class else name
        is_entry = name in ("main", "onCreate", "onStart", "onResume", "onBind", "onReceive")

        self.symbols.append(Symbol(
            name=name,
            full_name=full_name,
            type=SymbolType.METHOD,
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            is_entry_point=is_entry,
            importance=Importance.HIGH if is_entry else Importance.MEDIUM,
            module=_detect_module(self.file_path),
        ))

        # Extract calls
        self._extract_calls_from_node(node, full_name)

    def _visit_field_declaration(self, node: Node):
        # Java field
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                if name_node:
                    name = name_node.text.decode()
                    full_name = f"{self._current_class}.{name}" if self._current_class else name
                    self.symbols.append(Symbol(
                        name=name,
                        full_name=full_name,
                        type=SymbolType.FIELD,
                        line=node.start_point[0] + 1,
                        importance=Importance.LOW,
                    ))

    def _visit_import_declaration(self, node: Node):
        # Java import
        for child in node.children:
            if child.type in ("scoped_identifier", "identifier", "asterisk"):
                target = child.text.decode()
                self.imports.append(ImportEntry(
                    file_id=0,  # Will be updated later
                    target=target,
                    import_type="import",
                    line=node.start_point[0] + 1,
                ))

    def _visit_preproc_include(self, node: Node):
        # C/C++ #include
        for child in node.children:
            if child.type in ("string_literal", "system_lib_string"):
                target = child.text.decode().strip('"<>')
                self.imports.append(ImportEntry(
                    file_id=0,
                    target=target,
                    import_type="include",
                    line=node.start_point[0] + 1,
                ))

    # --- Helpers ---

    def _get_func_name(self, node: Node) -> Optional[str]:
        decl = node.child_by_field_name("declarator")
        if not decl:
            return None

        # Navigate through pointer/array declarators
        current = decl
        while current and current.type in ("pointer_declarator", "array_declarator"):
            current = current.child_by_field_name("declarator")
            if not current:
                break

        if current and current.type in ("function_declarator", "identifier"):
            name_node = current.child_by_field_name("declarator") or current
            if name_node:
                return name_node.text.decode()

        return None

    def _extract_calls_from_node(self, node: Node, caller_name: str):
        """Extract function call expressions from a node."""
        call_nodes = _find_nodes_by_type(node, "call_expression")
        for call_node in call_nodes:
            func_node = call_node.child_by_field_name("function")
            if func_node:
                callee_name = func_node.text.decode()
                # Simplify: remove object prefix for readability but keep full reference
                self.calls.append(CallRelation(
                    caller_name=caller_name,
                    callee_name=callee_name,
                    call_type=CallType.DIRECT,
                    line=call_node.start_point[0] + 1,
                ))

        # Also handle method_invocation (Java)
        method_calls = _find_nodes_by_type(node, "method_invocation")
        for mc in method_calls:
            obj_node = mc.child_by_field_name("object")
            name_node = mc.child_by_field_name("name")
            if name_node:
                callee = name_node.text.decode()
                if obj_node:
                    callee = f"{obj_node.text.decode()}.{callee}"
                self.calls.append(CallRelation(
                    caller_name=caller_name,
                    callee_name=callee,
                    call_type=CallType.VIRTUAL,
                    line=mc.start_point[0] + 1,
                ))


def _find_nodes_by_type(node: Node, type_name: str) -> list[Node]:
    results = []
    _collect_by_type(node, type_name, results)
    return results


def _collect_by_type(node: Node, type_name: str, results: list):
    if node.type == type_name:
        results.append(node)
    for child in node.children:
        _collect_by_type(child, type_name, results)


def _detect_module(path: str) -> Optional[str]:
    parts = Path(path).parts
    if len(parts) > 1:
        return parts[0]
    return None


# --- Smali Parser (regex-based) ---

SMALI_CLASS_RE = re.compile(r'^\.class\s+(?:[\w/]+\s+)*L([\w/$]+);', re.MULTILINE)
SMALI_METHOD_RE = re.compile(
    r'^\.method\s+(?:[\w]+\s+)*(\w+)\s*\(([^)]*)\)(.+)$', re.MULTILINE
)
SMALI_INVOKE_RE = re.compile(
    r'invoke-\w+\s+\{[^}]*\},\s*L([\w/$]+);->(\w+)\(', re.MULTILINE
)
SMALI_FIELD_RE = re.compile(
    r'^\.field\s+(?:[\w]+\s+)*(\w+)\s*:', re.MULTILINE
)
SMALI_SUPER_RE = re.compile(r'^\.super\s+L([\w/$]+);', re.MULTILINE)


def _parse_smali(file_path: Path, root: Path) -> dict:
    rel_path = str(file_path.relative_to(root)).replace("\\", "/")

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"file": FileEntry(path=rel_path, language="Smali"), "symbols": [], "calls": [], "imports": []}

    symbols: list[Symbol] = []
    calls: list[CallRelation] = []

    # Class name
    class_match = SMALI_CLASS_RE.search(source)
    class_name = class_match.group(1).replace("/", ".") if class_match else None
    class_short = class_name.split("$")[-1].split(".")[-1] if class_name else None

    if class_short:
        is_entry = _is_android_entry(class_name or "")
        symbols.append(Symbol(
            name=class_short,
            full_name=class_name,
            type=SymbolType.CLASS,
            is_entry_point=is_entry,
            importance=Importance.HIGH if is_entry else Importance.MEDIUM,
            module=_detect_module(rel_path),
        ))

    # Methods
    for m in SMALI_METHOD_RE.finditer(source):
        method_name = m.group(1)
        if method_name.startswith("<"):
            continue
        full_name = f"{class_name}.{method_name}" if class_name else method_name
        is_entry = _is_android_entry_method(method_name, class_name or "")

        symbols.append(Symbol(
            name=method_name,
            full_name=full_name,
            type=SymbolType.METHOD,
            importance=Importance.HIGH if is_entry else Importance.LOW,
            module=_detect_module(rel_path),
        ))

    # Fields
    for m in SMALI_FIELD_RE.finditer(source):
        field_name = m.group(1)
        symbols.append(Symbol(
            name=field_name,
            full_name=f"{class_name}.{field_name}" if class_name else field_name,
            type=SymbolType.FIELD,
            importance=Importance.LOW,
        ))

    # Invoke calls
    if class_name:
        for m in SMALI_INVOKE_RE.finditer(source):
            callee_class = m.group(1).replace("/", ".")
            callee_method = m.group(2)
            callee = f"{callee_class}.{callee_method}"
            calls.append(CallRelation(
                caller_name=class_name,
                callee_name=callee,
                call_type=CallType.VIRTUAL,
            ))

    file_entry = FileEntry(
        path=rel_path,
        language="Smali",
        size=file_path.stat().st_size,
        module=_detect_module(rel_path),
    )

    return {"file": file_entry, "symbols": symbols, "calls": calls, "imports": []}


def _is_android_entry(class_name: str) -> bool:
    patterns = ["Activity", "Service", "Receiver", "Provider", "Application"]
    return any(p in class_name for p in patterns)


def _is_android_entry_method(method_name: str, class_name: str) -> bool:
    entry_methods = {
        "onCreate", "onStart", "onResume", "onBind", "onReceive",
        "JNI_OnLoad", "main",
    }
    return method_name in entry_methods
