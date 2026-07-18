"""Static source-edge discovery for Python and TypeScript deliverables."""

from __future__ import annotations

import ast
import re
import warnings
from pathlib import Path
from typing import Sequence

from .models import ImportEdge
from .models import PYTHON_SUFFIXES
from .models import SOURCE_SUFFIXES
from .models import TYPESCRIPT_SUFFIXES
from .models import Violation
from .models import _JavaScriptToken
from .models import _is_denied_repository_path
from .models import _relative_to_root

def _module_targets_ee(module: str) -> bool:
    normalized = module.strip().lstrip(".")
    return "ee" in (component for component in normalized.split(".") if component)


def _constant_python_string(node: ast.expr) -> str | None:
    """Evaluate only syntax that is unambiguously a constant string."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_python_string(node.left)
        right = _constant_python_string(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not isinstance(value, ast.Constant) or not isinstance(
                value.value, str
            ):
                return None
            parts.append(value.value)
        return "".join(parts)
    return None


def _scan_python_imports(
    text: str, display_path: str
) -> tuple[list[ImportEdge], list[Violation]]:
    edges: list[ImportEdge] = []
    violations: list[Violation] = []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text, filename=display_path)
    except SyntaxError as error:
        violations.append(
            Violation(
                "SOURCE_PARSE_ERROR",
                display_path,
                error.lineno or 0,
                f"cannot parse Python source: {error.msg}",
            )
        )
        return edges, violations

    importlib_names = {"importlib"}
    import_module_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_names.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level and not module:
                modules.extend(alias.name for alias in node.names)
            else:
                modules.append(module)
        elif isinstance(node, ast.Call) and node.args:
            function_name = ""
            if isinstance(node.func, ast.Name):
                function_name = node.func.id
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
            ):
                function_name = f"{node.func.value.id}.{node.func.attr}"
            dynamic_import_functions = {
                "__import__",
                *import_module_names,
                *(f"{name}.import_module" for name in importlib_names),
            }
            if function_name in dynamic_import_functions:
                constant_module = _constant_python_string(node.args[0])
                if constant_module:
                    modules.append(constant_module)

        for module in modules:
            if not module:
                continue
            edge = ImportEdge(
                source_path=display_path,
                line=getattr(node, "lineno", 0),
                specifier=module,
                language="python",
            )
            edges.append(edge)
            if _module_targets_ee(module):
                violations.append(
                    Violation(
                        "PYTHON_EE_IMPORT",
                        display_path,
                        edge.line,
                        f"import edge targets forbidden module {module!r}",
                    )
                )
    return edges, violations


def _javascript_tokens(text: str) -> list[_JavaScriptToken]:
    """Tokenize the small JS/TS subset needed to find module specifiers.

    This is deliberately not a JavaScript parser. It is, however, lexical
    rather than regex based, so comments, quoted text, escaped module names and
    multiline import declarations cannot hide an import edge.
    """

    tokens: list[_JavaScriptToken] = []
    index = 0
    line = 1
    while index < len(text):
        character = text[index]
        next_character = text[index + 1] if index + 1 < len(text) else ""
        if character.isspace():
            if character == "\n":
                line += 1
            index += 1
            continue
        if character == "/" and next_character == "/":
            index += 2
            while index < len(text) and text[index] != "\n":
                index += 1
            continue
        if character == "/" and next_character == "*":
            index += 2
            while index < len(text):
                if text[index] == "\n":
                    line += 1
                if text[index : index + 2] == "*/":
                    index += 2
                    break
                index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            token_line = line
            index += 1
            value: list[str] = []
            interpolated = False
            while index < len(text):
                character = text[index]
                if character == quote:
                    index += 1
                    break
                if quote == "`" and text[index : index + 2] == "${":
                    interpolated = True
                if character == "\\" and index + 1 < len(text):
                    escaped = text[index + 1]
                    simple_escapes = {
                        "n": "\n",
                        "r": "\r",
                        "t": "\t",
                        "b": "\b",
                        "f": "\f",
                        "v": "\v",
                        "0": "\0",
                        "\\": "\\",
                        "'": "'",
                        '"': '"',
                        "`": "`",
                    }
                    if escaped in simple_escapes:
                        value.append(simple_escapes[escaped])
                        index += 2
                        continue
                    if escaped == "x" and re.fullmatch(
                        r"[0-9a-fA-F]{2}", text[index + 2 : index + 4]
                    ):
                        value.append(chr(int(text[index + 2 : index + 4], 16)))
                        index += 4
                        continue
                    if escaped == "u":
                        if text[index + 2 : index + 3] == "{":
                            closing = text.find("}", index + 3)
                            digits = text[index + 3 : closing] if closing >= 0 else ""
                            if digits and re.fullmatch(r"[0-9a-fA-F]{1,6}", digits):
                                value.append(chr(int(digits, 16)))
                                index = closing + 1
                                continue
                        digits = text[index + 2 : index + 6]
                        if re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                            value.append(chr(int(digits, 16)))
                            index += 6
                            continue
                    if escaped == "\n":
                        line += 1
                        index += 2
                        continue
                    value.append(escaped)
                    index += 2
                    continue
                if character == "\n":
                    line += 1
                value.append(character)
                index += 1
            tokens.append(
                _JavaScriptToken(
                    kind="dynamic_string" if interpolated else "string",
                    value="".join(value),
                    line=token_line,
                )
            )
            continue
        if character.isalpha() or character in {"_", "$"}:
            start = index
            index += 1
            while index < len(text) and (
                text[index].isalnum() or text[index] in {"_", "$"}
            ):
                index += 1
            tokens.append(_JavaScriptToken("word", text[start:index], line))
            continue
        tokens.append(_JavaScriptToken("punct", character, line))
        index += 1
    return tokens


def _javascript_import_specifiers(text: str) -> list[tuple[str, int]]:
    tokens = _javascript_tokens(text)
    specifiers: list[tuple[str, int]] = []
    for index, token in enumerate(tokens):
        next_token = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.kind == "word" and token.value in {"import", "require"}:
            if (
                next_token is not None
                and next_token.kind == "punct"
                and next_token.value == "("
                and index + 2 < len(tokens)
                and tokens[index + 2].kind == "string"
            ):
                value = tokens[index + 2]
                specifiers.append((value.value, value.line))
                continue
        if token.kind != "word" or token.value not in {"import", "export"}:
            continue
        if next_token is not None and next_token.kind == "string":
            specifiers.append((next_token.value, next_token.line))
            continue
        for candidate_index in range(index + 1, min(index + 257, len(tokens))):
            candidate = tokens[candidate_index]
            if candidate.kind == "punct" and candidate.value == ";":
                break
            if (
                candidate_index > index + 1
                and candidate.kind == "word"
                and candidate.value in {"import", "export"}
            ):
                break
            if candidate.kind == "word" and candidate.value == "from":
                value_index = candidate_index + 1
                if (
                    value_index < len(tokens)
                    and tokens[value_index].kind == "string"
                ):
                    value = tokens[value_index]
                    specifiers.append((value.value, value.line))
                break
    return specifiers


def _resolve_typescript_import(
    specifier: str,
    source_file: Path | None,
    repository_root: Path | None,
) -> str | None:
    if repository_root is None:
        return None
    if specifier.startswith("@/"):
        candidate = repository_root / "web" / "src" / specifier[2:]
    elif specifier.startswith(".") and source_file is not None:
        candidate = source_file.parent / specifier
    elif specifier.startswith(("backend/", "web/")):
        candidate = repository_root / specifier
    else:
        return None
    return _relative_to_root(candidate, repository_root)


def _typescript_specifier_targets_ee(specifier: str) -> bool:
    components = [
        component
        for component in specifier.replace("\\", "/").split("/")
        if component
    ]
    return "ee" in components


def _scan_typescript_imports(
    text: str,
    display_path: str,
    source_file: Path | None,
    repository_root: Path | None,
    denied_prefixes: Sequence[str],
) -> tuple[list[ImportEdge], list[Violation]]:
    edges: list[ImportEdge] = []
    violations: list[Violation] = []
    seen: set[tuple[int, str]] = set()
    for specifier, line in _javascript_import_specifiers(text):
        dedupe_key = (line, specifier)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        resolved_path = _resolve_typescript_import(
            specifier, source_file, repository_root
        )
        edge = ImportEdge(
            source_path=display_path,
            line=line,
            specifier=specifier,
            language="typescript",
            resolved_path=resolved_path,
        )
        edges.append(edge)
        targets_ee = _typescript_specifier_targets_ee(specifier) or (
            resolved_path is not None
            and _is_denied_repository_path(resolved_path, denied_prefixes)
        )
        if targets_ee:
            detail = f"import edge targets forbidden module {specifier!r}"
            if resolved_path is not None:
                detail += f" ({resolved_path})"
            violations.append(
                Violation(
                    "TYPESCRIPT_EE_IMPORT",
                    display_path,
                    edge.line,
                    detail,
                )
            )
    return edges, violations


def scan_source_file(
    source_file: Path,
    repository_root: Path,
    denied_prefixes: Sequence[str],
) -> list[Violation]:
    display_path = _relative_to_root(source_file, repository_root) or str(source_file)
    try:
        text = source_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [
            Violation(
                "SOURCE_READ_ERROR",
                display_path,
                0,
                f"cannot read source: {error}",
            )
        ]

    if source_file.suffix.lower() in PYTHON_SUFFIXES:
        return _scan_python_imports(text, display_path)[1]
    if source_file.suffix.lower() in TYPESCRIPT_SUFFIXES:
        return _scan_typescript_imports(
            text,
            display_path,
            source_file,
            repository_root,
            denied_prefixes,
        )[1]
    return []


def _expand_explicit_source(
    source_path: Path,
    repository_root: Path,
    denied_prefixes: Sequence[str],
) -> tuple[set[Path], list[Violation]]:
    sources: set[Path] = set()
    violations: list[Violation] = []
    display_path = _relative_to_root(source_path, repository_root) or str(source_path)
    if not source_path.exists():
        return sources, [
            Violation(
                "SOURCE_PATH_MISSING",
                display_path,
                0,
                "explicit source path does not exist",
            )
        ]
    candidates = (
        (candidate for candidate in source_path.rglob("*") if candidate.is_file())
        if source_path.is_dir()
        else (source_path,)
    )
    for candidate in candidates:
        repository_path = _relative_to_root(candidate, repository_root)
        if repository_path is None:
            continue
        if _is_denied_repository_path(repository_path, denied_prefixes):
            continue
        if candidate.suffix.lower() in SOURCE_SUFFIXES:
            sources.add(candidate)
    return sources, violations
