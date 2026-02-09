"""Rust parser using tree-sitter."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter_rust as ts_rust
from tree_sitter import Language, Node, Parser

from hackmenot.parsers.base import BaseParser


@dataclass
class RustCallInfo:
    """Information about a function/method call in Rust."""

    name: str
    args: list[str] = field(default_factory=list)
    is_unsafe_context: bool = False
    line: int = 0
    column: int = 0


@dataclass
class RustMacroInfo:
    """Information about a macro invocation in Rust."""

    name: str
    args: list[str] = field(default_factory=list)
    line: int = 0
    column: int = 0


@dataclass
class RustUnsafeBlockInfo:
    """Information about an unsafe block in Rust."""

    block_type: str  # "block", "function", "trait_impl"
    line_start: int = 0
    line_end: int = 0
    column: int = 0


@dataclass
class RustStringInfo:
    """Information about a string literal in Rust."""

    value: str
    is_raw: bool = False
    is_formatted: bool = False
    line: int = 0
    column: int = 0


@dataclass
class RustAssignmentInfo:
    """Information about a variable assignment in Rust."""

    target: str
    value: str = ""
    line: int = 0
    column: int = 0


@dataclass
class RustParseResult:
    """Result of parsing a Rust file."""

    file_path: Path = field(default_factory=lambda: Path("<string>"))
    has_error: bool = False
    error_message: str | None = None
    _calls: list[RustCallInfo] = field(default_factory=list)
    _macros: list[RustMacroInfo] = field(default_factory=list)
    _unsafe_blocks: list[RustUnsafeBlockInfo] = field(default_factory=list)
    _strings: list[RustStringInfo] = field(default_factory=list)
    _imports: list[str] = field(default_factory=list)
    _assignments: list[RustAssignmentInfo] = field(default_factory=list)
    _raw_tree: Any = None

    def get_calls(self) -> list[RustCallInfo]:
        """Get all function/method calls."""
        return self._calls

    def get_macros(self) -> list[RustMacroInfo]:
        """Get all macro invocations."""
        return self._macros

    def get_unsafe_blocks(self) -> list[RustUnsafeBlockInfo]:
        """Get all unsafe blocks."""
        return self._unsafe_blocks

    def get_strings(self) -> list[RustStringInfo]:
        """Get all string literals."""
        return self._strings

    def get_imports(self) -> list[str]:
        """Get all import paths."""
        return self._imports

    def get_assignments(self) -> list[RustAssignmentInfo]:
        """Get all variable assignments."""
        return self._assignments


class RustParser(BaseParser):
    """Parser for Rust source files using tree-sitter."""

    SUPPORTED_EXTENSIONS = {".rs"}

    def __init__(self) -> None:
        """Initialize the parser with tree-sitter Rust language."""
        self._language = Language(ts_rust.language())
        self._parser = Parser(self._language)

    def parse_file(self, file_path: Path) -> RustParseResult:
        """Parse a Rust file."""
        try:
            source = file_path.read_text(encoding="utf-8")
            result = self.parse_string(source, str(file_path))
            result.file_path = file_path
            return result
        except FileNotFoundError as e:
            return RustParseResult(
                file_path=file_path,
                has_error=True,
                error_message=f"File not found: {e}",
            )
        except (UnicodeDecodeError, OSError) as e:
            return RustParseResult(
                file_path=file_path,
                has_error=True,
                error_message=str(e),
            )

    def parse_string(self, source: str, filename: str = "<string>") -> RustParseResult:
        """Parse Rust source code string."""
        file_path = Path(filename)

        tree = self._parser.parse(bytes(source, "utf-8"))

        extractor = _RustExtractor(source)
        extractor.walk(tree.root_node)

        return RustParseResult(
            file_path=file_path,
            _calls=extractor.calls,
            _macros=extractor.macros,
            _unsafe_blocks=extractor.unsafe_blocks,
            _strings=extractor.strings,
            _imports=extractor.imports,
            _assignments=extractor.assignments,
            _raw_tree=tree,
        )


class _RustExtractor:
    """Walks the Rust AST and extracts security-relevant patterns."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.calls: list[RustCallInfo] = []
        self.macros: list[RustMacroInfo] = []
        self.unsafe_blocks: list[RustUnsafeBlockInfo] = []
        self.strings: list[RustStringInfo] = []
        self.imports: list[str] = []
        self.assignments: list[RustAssignmentInfo] = []
        self._in_unsafe = False  # Track if we're inside an unsafe block

    def walk(self, node: Node) -> None:
        """Walk the AST tree and extract patterns."""
        self._visit(node)

    def _visit(self, node: Node) -> None:
        """Visit a node and dispatch to the appropriate handler."""
        # Check for unsafe context
        if node.type == "unsafe_block":
            self._visit_unsafe_block(node)
        elif node.type == "function_item" and self._has_unsafe_keyword(node):
            self._visit_unsafe_function(node)
        elif node.type == "call_expression":
            self._visit_call_expression(node)
        elif node.type == "macro_invocation":
            self._visit_macro_invocation(node)
        elif node.type == "let_declaration":
            self._visit_let_declaration(node)
        elif node.type == "string_literal":
            self._visit_string_literal(node)
        elif node.type == "raw_string_literal":
            self._visit_raw_string_literal(node)
        elif node.type == "use_declaration":
            self._visit_use_declaration(node)

        # Recursively visit children
        for child in node.children:
            self._visit(child)

    def _has_unsafe_keyword(self, node: Node) -> bool:
        """Check if a function has the 'unsafe' keyword."""
        return any(child.type == "unsafe" for child in node.children)

    def _visit_unsafe_block(self, node: Node) -> None:
        """Extract unsafe block information."""
        line_start = node.start_point[0] + 1
        line_end = node.end_point[0] + 1
        column = node.start_point[1]

        self.unsafe_blocks.append(
            RustUnsafeBlockInfo(
                block_type="block",
                line_start=line_start,
                line_end=line_end,
                column=column,
            )
        )

        # Set unsafe context for nested calls
        old_unsafe = self._in_unsafe
        self._in_unsafe = True
        for child in node.children:
            self._visit(child)
        self._in_unsafe = old_unsafe

    def _visit_unsafe_function(self, node: Node) -> None:
        """Extract unsafe function information."""
        line_start = node.start_point[0] + 1
        line_end = node.end_point[0] + 1
        column = node.start_point[1]

        self.unsafe_blocks.append(
            RustUnsafeBlockInfo(
                block_type="function",
                line_start=line_start,
                line_end=line_end,
                column=column,
            )
        )

    def _visit_call_expression(self, node: Node) -> None:
        """Extract function/method call information."""
        # Get the function name (could be simple or path-qualified)
        function_node = node.child_by_field_name("function")
        if not function_node:
            return

        name = self._extract_call_name(function_node)
        if not name:
            return

        # Extract arguments
        args_node = node.child_by_field_name("arguments")
        args: list[str] = []
        if args_node:
            for arg in args_node.children:
                if arg.type != "(" and arg.type != ")" and arg.type != ",":
                    arg_text = self._get_node_text(arg)
                    if arg_text:
                        args.append(arg_text)

        line = node.start_point[0] + 1
        column = node.start_point[1]

        self.calls.append(
            RustCallInfo(
                name=name,
                args=args,
                is_unsafe_context=self._in_unsafe,
                line=line,
                column=column,
            )
        )

    def _extract_call_name(self, node: Node) -> str:
        """Extract the name of a function call, handling paths and field expressions."""
        if node.type == "identifier":
            return self._get_node_text(node) or ""
        elif node.type == "scoped_identifier":
            # e.g., std::ptr::write
            parts: list[str] = []
            for child in node.children:
                if child.type != "::":
                    text = self._get_node_text(child)
                    if text:
                        parts.append(text)
            return "::".join(parts)
        elif node.type == "field_expression":
            # e.g., vec.push()
            base = node.child_by_field_name("value")
            field = node.child_by_field_name("field")
            base_text = self._get_node_text(base) if base else ""
            field_text = self._get_node_text(field) if field else ""
            if base_text and field_text:
                return f"{base_text}.{field_text}"
        return self._get_node_text(node) or ""

    def _visit_macro_invocation(self, node: Node) -> None:
        """Extract macro invocation information."""
        # Get macro name
        macro_node = node.child_by_field_name("macro")
        if not macro_node:
            return

        name = self._get_node_text(macro_node)
        if not name:
            return

        # Add ! to macro name if not present
        if not name.endswith("!"):
            name += "!"

        # Extract macro arguments
        token_tree = node.child_by_field_name("token_tree")
        args: list[str] = []
        if token_tree:
            arg_text = self._get_node_text(token_tree)
            if arg_text:
                args.append(arg_text)

        line = node.start_point[0] + 1
        column = node.start_point[1]

        self.macros.append(RustMacroInfo(name=name, args=args, line=line, column=column))

    def _visit_let_declaration(self, node: Node) -> None:
        """Extract variable assignment information."""
        # Get the pattern (variable name)
        pattern = node.child_by_field_name("pattern")
        if not pattern:
            return

        target = self._get_node_text(pattern)
        if not target:
            return

        # Get the value
        value_node = node.child_by_field_name("value")
        value = ""
        if value_node:
            value = self._get_node_text(value_node) or ""

        line = node.start_point[0] + 1
        column = node.start_point[1]

        self.assignments.append(
            RustAssignmentInfo(target=target, value=value, line=line, column=column)
        )

    def _visit_string_literal(self, node: Node) -> None:
        """Extract string literal information."""
        text = self._get_node_text(node)
        if not text:
            return

        # Remove quotes
        value = text.strip('"')

        line = node.start_point[0] + 1
        column = node.start_point[1]

        self.strings.append(
            RustStringInfo(value=value, is_raw=False, is_formatted=False, line=line, column=column)
        )

    def _visit_raw_string_literal(self, node: Node) -> None:
        """Extract raw string literal information."""
        text = self._get_node_text(node)
        if not text:
            return

        # Raw strings can be r"...", r#"..."#, r##"..."##, etc.
        # Extract the content between the delimiters
        value = text

        line = node.start_point[0] + 1
        column = node.start_point[1]

        self.strings.append(
            RustStringInfo(value=value, is_raw=True, is_formatted=False, line=line, column=column)
        )

    def _visit_use_declaration(self, node: Node) -> None:
        """Extract use declaration (import) information."""
        # Get the full use path
        text = self._get_node_text(node)
        if not text:
            return

        # Clean up the import path (remove 'use' and ';')
        import_path = text.replace("use", "").replace(";", "").strip()

        self.imports.append(import_path)

    def _get_node_text(self, node: Node | None) -> str | None:
        """Extract the source text for a given node."""
        if not node:
            return None
        try:
            return self.source[node.start_byte : node.end_byte]
        except (IndexError, AttributeError):
            return None
