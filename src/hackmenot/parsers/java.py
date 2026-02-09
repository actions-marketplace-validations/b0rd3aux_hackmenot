"""Java parser using tree-sitter."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter_java as ts_java
from tree_sitter import Language, Node, Parser

from hackmenot.parsers.base import BaseParser


@dataclass
class JavaMethodInvocationInfo:
    """Information about a method invocation in Java."""

    receiver: str | None
    method_name: str
    arguments: list[str] = field(default_factory=list)
    line: int = 0
    column: int = 0


@dataclass
class JavaObjectCreationInfo:
    """Information about an object creation in Java."""

    class_name: str
    arguments: list[str] = field(default_factory=list)
    line: int = 0
    column: int = 0


@dataclass
class JavaStringConcatInfo:
    """Information about string concatenation in Java."""

    parts: list[str] = field(default_factory=list)
    line: int = 0
    column: int = 0
    in_sql_context: bool = False


@dataclass
class JavaAnnotationInfo:
    """Information about an annotation in Java."""

    name: str
    parameters: dict[str, str] = field(default_factory=dict)
    target_element: str = ""
    line: int = 0
    column: int = 0


@dataclass
class JavaAssignmentInfo:
    """Information about a variable assignment in Java."""

    target: str
    value: str = ""
    line: int = 0
    column: int = 0


@dataclass
class JavaParseResult:
    """Result of parsing a Java file."""

    file_path: Path = field(default_factory=lambda: Path("<string>"))
    has_error: bool = False
    error_message: str | None = None
    _method_invocations: list[JavaMethodInvocationInfo] = field(default_factory=list)
    _object_creations: list[JavaObjectCreationInfo] = field(default_factory=list)
    _string_concats: list[JavaStringConcatInfo] = field(default_factory=list)
    _annotations: list[JavaAnnotationInfo] = field(default_factory=list)
    _imports: list[str] = field(default_factory=list)
    _assignments: list[JavaAssignmentInfo] = field(default_factory=list)
    _raw_tree: Any = None

    def get_method_invocations(self) -> list[JavaMethodInvocationInfo]:
        """Get all method invocations."""
        return self._method_invocations

    def get_object_creations(self) -> list[JavaObjectCreationInfo]:
        """Get all object creations."""
        return self._object_creations

    def get_string_concats(self) -> list[JavaStringConcatInfo]:
        """Get all string concatenations."""
        return self._string_concats

    def get_annotations(self) -> list[JavaAnnotationInfo]:
        """Get all annotations."""
        return self._annotations

    def get_imports(self) -> list[str]:
        """Get all import statements."""
        return self._imports

    def get_assignments(self) -> list[JavaAssignmentInfo]:
        """Get all variable assignments."""
        return self._assignments


class JavaParser(BaseParser):
    """Parser for Java source files using tree-sitter."""

    SUPPORTED_EXTENSIONS = {".java"}

    def __init__(self) -> None:
        """Initialize the parser with tree-sitter Java language."""
        self._language = Language(ts_java.language())
        self._parser = Parser(self._language)

    def parse_file(self, file_path: Path) -> JavaParseResult:
        """Parse a Java file."""
        try:
            source = file_path.read_text(encoding="utf-8")
            result = self.parse_string(source, str(file_path))
            result.file_path = file_path
            return result
        except FileNotFoundError as e:
            return JavaParseResult(
                file_path=file_path,
                has_error=True,
                error_message=f"File not found: {e}",
            )
        except (UnicodeDecodeError, OSError) as e:
            return JavaParseResult(
                file_path=file_path,
                has_error=True,
                error_message=str(e),
            )

    def parse_string(self, source: str, filename: str = "<string>") -> JavaParseResult:
        """Parse Java source code string."""
        file_path = Path(filename)

        tree = self._parser.parse(bytes(source, "utf-8"))

        extractor = _JavaExtractor(source)
        extractor.walk(tree.root_node)

        return JavaParseResult(
            file_path=file_path,
            _method_invocations=extractor.method_invocations,
            _object_creations=extractor.object_creations,
            _string_concats=extractor.string_concats,
            _annotations=extractor.annotations,
            _imports=extractor.imports,
            _assignments=extractor.assignments,
            _raw_tree=tree,
        )


class _JavaExtractor:
    """Walks the Java AST and extracts security-relevant patterns."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.method_invocations: list[JavaMethodInvocationInfo] = []
        self.object_creations: list[JavaObjectCreationInfo] = []
        self.string_concats: list[JavaStringConcatInfo] = []
        self.annotations: list[JavaAnnotationInfo] = []
        self.imports: list[str] = []
        self.assignments: list[JavaAssignmentInfo] = []

    def walk(self, node: Node) -> None:
        """Walk the AST tree and extract patterns."""
        self._visit(node)

    def _visit(self, node: Node) -> None:
        """Visit a node and dispatch to the appropriate handler."""
        if node.type == "method_invocation":
            self._visit_method_invocation(node)
        elif node.type == "object_creation_expression":
            self._visit_object_creation(node)
        elif node.type == "binary_expression":
            self._visit_binary_expression(node)
        elif node.type == "marker_annotation" or node.type == "annotation":
            self._visit_annotation(node)
        elif node.type == "import_declaration":
            self._visit_import(node)
        elif node.type == "local_variable_declaration":
            self._visit_local_variable_declaration(node)

        # Recursively visit children
        for child in node.children:
            self._visit(child)

    def _visit_method_invocation(self, node: Node) -> None:
        """Extract method invocation information."""
        # Get the method name
        name_node = node.child_by_field_name("name")
        if not name_node:
            return

        method_name = self._get_node_text(name_node)
        if not method_name:
            return

        # Get the receiver/object
        object_node = node.child_by_field_name("object")
        receiver = None
        if object_node:
            receiver = self._get_node_text(object_node)

        # Extract arguments
        arguments_node = node.child_by_field_name("arguments")
        arguments: list[str] = []
        if arguments_node:
            for arg in arguments_node.children:
                if arg.type != "(" and arg.type != ")" and arg.type != ",":
                    arg_text = self._get_node_text(arg)
                    if arg_text:
                        arguments.append(arg_text)

        line = node.start_point[0] + 1
        column = node.start_point[1]

        self.method_invocations.append(
            JavaMethodInvocationInfo(
                receiver=receiver,
                method_name=method_name,
                arguments=arguments,
                line=line,
                column=column,
            )
        )

    def _visit_object_creation(self, node: Node) -> None:
        """Extract object creation information."""
        # Get the type/class name
        type_node = node.child_by_field_name("type")
        if not type_node:
            return

        class_name = self._get_node_text(type_node)
        if not class_name:
            return

        # Extract constructor arguments
        arguments_node = node.child_by_field_name("arguments")
        arguments: list[str] = []
        if arguments_node:
            for arg in arguments_node.children:
                if arg.type != "(" and arg.type != ")" and arg.type != ",":
                    arg_text = self._get_node_text(arg)
                    if arg_text:
                        arguments.append(arg_text)

        line = node.start_point[0] + 1
        column = node.start_point[1]

        self.object_creations.append(
            JavaObjectCreationInfo(
                class_name=class_name,
                arguments=arguments,
                line=line,
                column=column,
            )
        )

    def _visit_binary_expression(self, node: Node) -> None:
        """Extract binary expressions (including string concatenation)."""
        # Get the operator
        operator_node = node.child_by_field_name("operator")
        if not operator_node:
            return

        operator = self._get_node_text(operator_node)
        if operator != "+":
            return  # Only interested in + for string concat

        # Get left and right operands
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")

        parts: list[str] = []
        if left_node:
            left_text = self._get_node_text(left_node)
            if left_text:
                parts.append(left_text)
        if right_node:
            right_text = self._get_node_text(right_node)
            if right_text:
                parts.append(right_text)

        if parts:
            line = node.start_point[0] + 1
            column = node.start_point[1]

            # Simple heuristic for SQL context
            full_text = " + ".join(parts)
            in_sql = any(
                keyword.upper() in full_text.upper()
                for keyword in ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]
            )

            self.string_concats.append(
                JavaStringConcatInfo(
                    parts=parts,
                    line=line,
                    column=column,
                    in_sql_context=in_sql,
                )
            )

    def _visit_annotation(self, node: Node) -> None:
        """Extract annotation information."""
        # Get annotation name
        name_node = node.child_by_field_name("name")
        if not name_node:
            return

        name = self._get_node_text(name_node)
        if not name:
            return

        # Extract annotation parameters (if any)
        parameters: dict[str, str] = {}
        arguments_node = node.child_by_field_name("arguments")
        if arguments_node:
            # Simple extraction of annotation arguments
            args_text = self._get_node_text(arguments_node)
            if args_text:
                parameters["_raw"] = args_text

        line = node.start_point[0] + 1
        column = node.start_point[1]

        self.annotations.append(
            JavaAnnotationInfo(
                name=name,
                parameters=parameters,
                target_element="",  # Would need more context to determine
                line=line,
                column=column,
            )
        )

    def _visit_import(self, node: Node) -> None:
        """Extract import declaration information."""
        text = self._get_node_text(node)
        if not text:
            return

        # Clean up the import (remove 'import' and ';')
        import_path = text.replace("import", "").replace(";", "").strip()

        self.imports.append(import_path)

    def _visit_local_variable_declaration(self, node: Node) -> None:
        """Extract local variable declaration/assignment information."""
        # Find variable declarator
        for child in node.children:
            if child.type == "variable_declarator":
                # Get variable name
                name_node = child.child_by_field_name("name")
                if not name_node:
                    continue

                target = self._get_node_text(name_node)
                if not target:
                    continue

                # Get value (if present)
                value_node = child.child_by_field_name("value")
                value = ""
                if value_node:
                    value = self._get_node_text(value_node) or ""

                line = child.start_point[0] + 1
                column = child.start_point[1]

                self.assignments.append(
                    JavaAssignmentInfo(target=target, value=value, line=line, column=column)
                )

    def _get_node_text(self, node: Node | None) -> str | None:
        """Extract the source text for a given node."""
        if not node:
            return None
        try:
            return self.source[node.start_byte : node.end_byte]
        except (IndexError, AttributeError):
            return None
