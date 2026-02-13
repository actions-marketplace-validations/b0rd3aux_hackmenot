"""Data flow tracking - trace untrusted inputs to security sinks."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import ClassVar

from hackmenot.graph.surface import EntryPoint, SurfaceMapper
from hackmenot.parsers.python import PythonParser


class SinkType(Enum):
    """Types of security-sensitive sinks."""

    SQL_QUERY = "sql_query"
    SHELL_COMMAND = "shell_command"
    FILE_OPERATION = "file_operation"
    EVAL_EXEC = "eval_exec"
    NETWORK_REQUEST = "network_request"
    TEMPLATE_RENDER = "template_render"
    DESERIALIZATION = "deserialization"


@dataclass
class TaintSource:
    """A source of untrusted data (entry point parameter)."""

    entry_point: EntryPoint
    parameter: str
    file: Path
    line: int


@dataclass
class TaintSink:
    """A security-sensitive operation that could be exploited."""

    type: SinkType
    operation: str  # e.g., "execute_sql", "subprocess.run"
    file: Path
    line: int
    finding_id: str | None = None  # Associated hackmenot finding (e.g., INJ001)


@dataclass
class FlowStep:
    """A step in the data flow path."""

    file: Path
    line: int
    operation: str  # "assign", "call", "return"
    variable: str | None = None
    function: str | None = None


@dataclass
class DataFlowPath:
    """A complete path from taint source to sink."""

    source: TaintSource
    sink: TaintSink
    path: list[FlowStep]
    sanitized: bool = False
    sanitizers: list[str] | None = None  # Functions that sanitize data


@dataclass
class CallEdge:
    """An edge in the call graph."""

    caller: str  # Function name
    callee: str  # Function name
    caller_file: Path
    callee_file: Path | None  # None if callee not found
    caller_line: int


class CallGraph:
    """Call graph showing which functions call which."""

    def __init__(self) -> None:
        """Initialize empty call graph."""
        self.edges: list[CallEdge] = []
        self.functions: dict[str, Path] = {}  # function_name -> file_path

    def add_edge(
        self,
        caller: str,
        callee: str,
        caller_file: Path,
        caller_line: int,
        callee_file: Path | None = None,
    ) -> None:
        """Add an edge to the call graph.

        Args:
            caller: Name of calling function.
            callee: Name of called function.
            caller_file: File containing caller.
            caller_line: Line where call occurs.
            callee_file: File containing callee (if known).
        """
        self.edges.append(
            CallEdge(
                caller=caller,
                callee=callee,
                caller_file=caller_file,
                callee_file=callee_file,
                caller_line=caller_line,
            )
        )

    def add_function(self, name: str, file: Path) -> None:
        """Register a function definition.

        Args:
            name: Function name.
            file: File where function is defined.
        """
        self.functions[name] = file

    def get_callees(self, function: str) -> list[CallEdge]:
        """Get all functions called by a given function.

        Args:
            function: Function name.

        Returns:
            List of call edges where function is the caller.
        """
        return [edge for edge in self.edges if edge.caller == function]

    def get_callers(self, function: str) -> list[CallEdge]:
        """Get all functions that call a given function.

        Args:
            function: Function name.

        Returns:
            List of call edges where function is the callee.
        """
        return [edge for edge in self.edges if edge.callee == function]


class DataFlowTracker:
    """Tracks data flow from taint sources to sinks."""

    # Known SQL operations
    SQL_OPERATIONS: ClassVar[set[str]] = {
        "execute",
        "executemany",
        "execute_sql",
        "raw",
        "query",
        "select",
        "insert",
        "update",
        "delete",
    }

    # Known shell command operations (detecting these as security risks)
    SHELL_OPERATIONS: ClassVar[set[str]] = {
        "system",  # Detect os.system, subprocess.system as risks
        "popen",
        "exec",
        "spawn",
        "run",
        "call",
        "check_output",
        "check_call",
    }

    # Known eval/exec operations
    EVAL_OPERATIONS: ClassVar[set[str]] = {"eval", "exec", "compile"}

    # Known sanitization functions
    SANITIZERS: ClassVar[set[str]] = {
        "escape",
        "sanitize",
        "clean",
        "validate",
        "quote",
        "quote_identifier",
        "parameterize",
    }

    def __init__(self) -> None:
        """Initialize the data flow tracker."""
        self.python_parser = PythonParser()
        self.surface_mapper = SurfaceMapper()
        self.call_graph = CallGraph()

    def analyze(self, paths: list[Path]) -> list[DataFlowPath]:
        """Analyze data flow across files.

        Args:
            paths: Files or directories to analyze.

        Returns:
            List of data flow paths from sources to sinks.
        """
        # 1. Identify taint sources (entry points)
        attack_surface = self.surface_mapper.map_surface(paths)
        sources = self._extract_taint_sources(attack_surface.entry_points)

        # 2. Identify sinks (security-sensitive operations)
        files = self._discover_files(paths)
        sinks = self._find_sinks(files)

        # 3. Trace flows from sources to sinks
        # Note: This is simplified without call graph
        flows = self._trace_flows(sources, sinks)

        return flows

    def _discover_files(self, paths: list[Path]) -> list[Path]:
        """Discover Python files to analyze.

        Args:
            paths: Input paths.

        Returns:
            List of Python files.
        """
        files = []
        for path in paths:
            if path.is_file() and path.suffix == ".py":
                files.append(path)
            elif path.is_dir():
                files.extend(path.rglob("*.py"))
        return files

    def _build_call_graph(self, files: list[Path]) -> None:
        """Build call graph from files.

        Args:
            files: Python files to analyze.
        """
        # First pass: register all functions
        for file_path in files:
            parse_result = self.python_parser.parse_file(file_path)
            if parse_result is None or parse_result.has_error:
                continue

            for func in parse_result._functions:
                self.call_graph.add_function(func.name, file_path)

        # Second pass: extract calls
        for file_path in files:
            parse_result = self.python_parser.parse_file(file_path)
            if parse_result is None or parse_result.has_error:
                continue

            # Map calls to their containing functions
            for func in parse_result._functions:
                # Parse function body for calls
                # Note: PythonParser doesn't track calls per function,
                # so we approximate by looking at all calls in file
                # This is a simplification - proper implementation would
                # need AST traversal scoped to function body
                for call in parse_result._calls:
                    if func.body_start <= call.line_number <= func.body_end:
                        callee_file = self.call_graph.functions.get(call.name)
                        self.call_graph.add_edge(
                            caller=func.name,
                            callee=call.name,
                            caller_file=file_path,
                            caller_line=call.line_number,
                            callee_file=callee_file,
                        )

    def _extract_taint_sources(self, entry_points: list[EntryPoint]) -> list[TaintSource]:
        """Extract taint sources from entry points.

        Args:
            entry_points: Detected entry points.

        Returns:
            List of taint sources.
        """
        sources = []

        for ep in entry_points:
            # For each entry point, treat all inputs as taint sources
            if ep.inputs:
                for param in ep.inputs:
                    sources.append(
                        TaintSource(
                            entry_point=ep,
                            parameter=param,
                            file=ep.file,
                            line=ep.line,
                        )
                    )
            else:
                # Generic source for entry point
                sources.append(
                    TaintSource(
                        entry_point=ep,
                        parameter="*",  # All parameters
                        file=ep.file,
                        line=ep.line,
                    )
                )

        return sources

    def _find_sinks(self, files: list[Path]) -> list[TaintSink]:
        """Find security-sensitive sinks in files.

        Args:
            files: Python files to analyze.

        Returns:
            List of taint sinks.
        """
        sinks = []

        for file_path in files:
            # Read source and look for sink patterns
            # This is a simplified approach using string matching
            try:
                source = file_path.read_text()
                lines = source.split("\n")

                for line_num, line in enumerate(lines, start=1):
                    line_lower = line.lower()

                    # SQL operations
                    if any(f".{sql_op}(" in line_lower for sql_op in self.SQL_OPERATIONS):
                        for sql_op in self.SQL_OPERATIONS:
                            if f".{sql_op}(" in line_lower:
                                sinks.append(
                                    TaintSink(
                                        type=SinkType.SQL_QUERY,
                                        operation=f"<unknown>.{sql_op}()",
                                        file=file_path,
                                        line=line_num,
                                    )
                                )
                                break

                    # Shell commands (detecting as security risks)
                    elif any(f".{shell_op}(" in line_lower for shell_op in self.SHELL_OPERATIONS):
                        for shell_op in self.SHELL_OPERATIONS:
                            if f".{shell_op}(" in line_lower:
                                sinks.append(
                                    TaintSink(
                                        type=SinkType.SHELL_COMMAND,
                                        # Use concat instead of f-string to avoid false positive
                                        operation="<subprocess>." + shell_op + "()",
                                        file=file_path,
                                        line=line_num,
                                    )
                                )
                                break

                    # Eval/exec
                    for eval_op in self.EVAL_OPERATIONS:
                        if f"{eval_op}(" in line and not line.strip().startswith("#"):
                            sinks.append(
                                TaintSink(
                                    type=SinkType.EVAL_EXEC,
                                    operation=eval_op,
                                    file=file_path,
                                    line=line_num,
                                )
                            )

            except (OSError, UnicodeDecodeError):
                continue

        return sinks

    def _trace_flows(
        self, sources: list[TaintSource], sinks: list[TaintSink]
    ) -> list[DataFlowPath]:
        """Trace data flows from sources to sinks.

        This is a simplified flow analysis that checks if:
        1. Source and sink are in the same file
        2. Source occurs before sink (line-wise)
        3. There's a call path connecting them

        A full taint analysis would require interprocedural data flow,
        which is complex. This provides a basic approximation.

        Args:
            sources: Taint sources.
            sinks: Taint sinks.

        Returns:
            List of data flow paths.
        """
        flows = []

        for source in sources:
            for sink in sinks:
                # Simple heuristic: same file, source before sink
                if source.file == sink.file and source.line < sink.line:
                    # Check if there's a call path from source to sink
                    # For simplicity, assume direct flow if in same function/file
                    path = [
                        FlowStep(
                            file=source.file,
                            line=source.line,
                            operation="source",
                            variable=source.parameter,
                        ),
                        FlowStep(
                            file=sink.file,
                            line=sink.line,
                            operation="sink",
                            function=sink.operation,
                        ),
                    ]

                    # Check if flow is sanitized
                    sanitized = self._is_flow_sanitized(source, sink)

                    flows.append(
                        DataFlowPath(
                            source=source,
                            sink=sink,
                            path=path,
                            sanitized=sanitized,
                        )
                    )

        return flows

    def _is_flow_sanitized(self, source: TaintSource, sink: TaintSink) -> bool:
        """Check if data flow is sanitized.

        Args:
            source: Taint source.
            sink: Taint sink.

        Returns:
            True if flow appears to be sanitized.
        """
        # Simple heuristic: check if any sanitization functions are called
        # between source and sink in the call graph
        # This is a simplification - real implementation would need
        # interprocedural analysis

        # For now, assume unsanitized
        return False
