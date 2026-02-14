"""C/C++ parser using tree-sitter."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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
