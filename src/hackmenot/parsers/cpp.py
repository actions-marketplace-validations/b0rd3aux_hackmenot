"""C/C++ parser using tree-sitter."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter_cpp as ts_cpp
from tree_sitter import Language, Node, Parser

from hackmenot.parsers.base import BaseParser


@dataclass
class CppCallInfo:
    """Information about a function/method call in C/C++."""

    name: str
    args: list[str] = field(default_factory=list)
    line: int = 0
    column: int = 0


@dataclass
class CppUnsafeFunctionInfo:
    """Information about an unsafe function usage."""

    name: str
    args: list[str] = field(default_factory=list)
    has_size_check: bool = False
    line: int = 0
    column: int = 0


@dataclass
class CppPointerInfo:
    """Information about pointer operations."""

    operation: str  # "dereference", "arithmetic", "cast"
    expression: str
    line: int = 0
    column: int = 0


@dataclass
class CppArrayInfo:
    """Information about array access."""

    name: str
    index_expr: str
    is_fixed_size: bool = False
    size: int | None = None
    line: int = 0
    column: int = 0


@dataclass
class CppStringInfo:
    """Information about string literals."""

    value: str
    is_format_string: bool = False
    line: int = 0
    column: int = 0


@dataclass
class CppParseResult:
    """Result of parsing a C/C++ file."""

    file_path: Path = field(default_factory=lambda: Path("<string>"))
    has_error: bool = False
    error_message: str | None = None
    _calls: list[CppCallInfo] = field(default_factory=list)
    _unsafe_functions: list[CppUnsafeFunctionInfo] = field(default_factory=list)
    _pointers: list[CppPointerInfo] = field(default_factory=list)
    _arrays: list[CppArrayInfo] = field(default_factory=list)
    _strings: list[CppStringInfo] = field(default_factory=list)
    _includes: list[str] = field(default_factory=list)
    _raw_tree: Any = None

    def get_calls(self) -> list[CppCallInfo]:
        """Get all function/method calls."""
        return self._calls

    def get_unsafe_functions(self) -> list[CppUnsafeFunctionInfo]:
        """Get all unsafe function usages."""
        return self._unsafe_functions

    def get_pointers(self) -> list[CppPointerInfo]:
        """Get all pointer operations."""
        return self._pointers

    def get_arrays(self) -> list[CppArrayInfo]:
        """Get all array accesses."""
        return self._arrays

    def get_strings(self) -> list[CppStringInfo]:
        """Get all string literals."""
        return self._strings

    def get_includes(self) -> list[str]:
        """Get all include statements."""
        return self._includes


class CppParser(BaseParser):
    """C/C++ parser using tree-sitter-cpp."""

    def __init__(self):
        """Initialize C/C++ parser."""
        self.language = Language(ts_cpp.language())
        self.parser = Parser(self.language)

    def parse_file(self, file_path: Path) -> CppParseResult:
        """Parse a C/C++ file from disk."""
        try:
            source = file_path.read_text(encoding="utf-8")
            return self.parse_string(source, str(file_path))
        except UnicodeDecodeError:
            return CppParseResult(
                file_path=file_path, has_error=True, error_message="File is not valid UTF-8"
            )
        except OSError as e:
            return CppParseResult(
                file_path=file_path, has_error=True, error_message=f"Could not read file: {e}"
            )

    def parse_string(self, source: str, filename: str = "<string>") -> CppParseResult:
        """Parse C/C++ source code string."""
        try:
            tree = self.parser.parse(bytes(source, "utf-8"))

            if self._has_syntax_errors(tree.root_node):
                return CppParseResult(
                    file_path=Path(filename),
                    has_error=True,
                    error_message="Syntax errors in C/C++ code",
                )

            # Extract patterns
            calls = self._extract_calls(tree.root_node)
            includes = self._extract_includes(tree.root_node)
            strings = self._extract_strings(tree.root_node)

            return CppParseResult(
                file_path=Path(filename),
                _calls=calls,
                _includes=includes,
                _strings=strings,
                _raw_tree=tree,
            )

        except Exception as e:
            return CppParseResult(
                file_path=Path(filename), has_error=True, error_message=f"Parser error: {e}"
            )

    def _has_syntax_errors(self, node: Node) -> bool:
        """Check if tree has syntax errors."""
        if node.type == "ERROR":
            return True
        return any(self._has_syntax_errors(child) for child in node.children)

    def _extract_calls(self, node: Node) -> list[CppCallInfo]:
        """Extract function calls from AST."""
        calls: list[CppCallInfo] = []

        def visit(n: Node):
            if n.type == "call_expression":
                # Get function name
                func_node = n.child_by_field_name("function")
                if func_node:
                    func_name = func_node.text.decode("utf-8") if func_node.text else ""

                    # Get arguments
                    args_node = n.child_by_field_name("arguments")
                    args = []
                    if args_node:
                        for arg in args_node.children:
                            if arg.type != "," and arg.type != "(" and arg.type != ")":
                                args.append(arg.text.decode("utf-8") if arg.text else "")

                    calls.append(
                        CppCallInfo(
                            name=func_name,
                            args=args,
                            line=n.start_point[0] + 1,
                            column=n.start_point[1],
                        )
                    )

            for child in n.children:
                visit(child)

        visit(node)
        return calls

    def _extract_includes(self, node: Node) -> list[str]:
        """Extract #include statements."""
        includes: list[str] = []

        def visit(n: Node):
            if n.type == "preproc_include":
                path_node = n.child_by_field_name("path")
                if path_node and path_node.text:
                    includes.append(path_node.text.decode("utf-8"))

            for child in n.children:
                visit(child)

        visit(node)
        return includes

    def _extract_strings(self, node: Node) -> list[CppStringInfo]:
        """Extract string literals."""
        strings: list[CppStringInfo] = []

        def visit(n: Node):
            if n.type == "string_literal":
                value = n.text.decode("utf-8") if n.text else ""
                # Check if it's a format string (contains %)
                is_format = "%" in value

                strings.append(
                    CppStringInfo(
                        value=value,
                        is_format_string=is_format,
                        line=n.start_point[0] + 1,
                        column=n.start_point[1],
                    )
                )

            for child in n.children:
                visit(child)

        visit(node)
        return strings
