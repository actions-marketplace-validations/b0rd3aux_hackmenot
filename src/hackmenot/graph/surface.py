"""Attack surface mapping - identify entry points where untrusted data enters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from hackmenot.parsers.python import PythonParser


class EntryPointType(Enum):
    """Types of entry points in an application."""

    API_ENDPOINT = "api_endpoint"
    CLI_COMMAND = "cli_command"
    USER_INPUT = "user_input"
    WEBHOOK = "webhook"
    SOCKET = "socket"
    MESSAGE_QUEUE = "message_queue"
    FILE_UPLOAD = "file_upload"


@dataclass
class EntryPoint:
    """An entry point where untrusted data enters the application."""

    name: str
    type: EntryPointType
    file: Path
    line: int
    http_method: str | None = None  # GET, POST, etc.
    route: str | None = None  # /api/users/{id}
    auth_required: bool = False
    inputs: list[str] | None = None
    framework: str | None = None  # Flask, FastAPI, Express, etc.


@dataclass
class AttackSurface:
    """Complete attack surface of an application."""

    entry_points: list[EntryPoint]
    total_count: int
    public_count: int  # No auth required
    authenticated_count: int


class SurfaceMapper:
    """Maps attack surface by detecting entry points."""

    def __init__(self) -> None:
        """Initialize the surface mapper."""
        self.python_parser = PythonParser()

    def map_surface(self, paths: list[Path]) -> AttackSurface:
        """Map attack surface across multiple files/directories.

        Args:
            paths: List of files or directories to analyze.

        Returns:
            AttackSurface with all detected entry points.
        """
        entry_points: list[EntryPoint] = []

        # Discover all Python files
        files = self._discover_files(paths)

        # Analyze each file for entry points
        for file_path in files:
            file_entry_points = self._analyze_file(file_path)
            entry_points.extend(file_entry_points)

        # Calculate metrics
        public_count = sum(1 for ep in entry_points if not ep.auth_required)
        auth_count = sum(1 for ep in entry_points if ep.auth_required)

        return AttackSurface(
            entry_points=entry_points,
            total_count=len(entry_points),
            public_count=public_count,
            authenticated_count=auth_count,
        )

    def _discover_files(self, paths: list[Path]) -> list[Path]:
        """Discover Python files to analyze.

        Args:
            paths: Input paths (files or directories).

        Returns:
            List of Python files to analyze.
        """
        files = []
        for path in paths:
            if path.is_file() and path.suffix == ".py":
                files.append(path)
            elif path.is_dir():
                files.extend(path.rglob("*.py"))
        return files

    def _analyze_file(self, file_path: Path) -> list[EntryPoint]:
        """Analyze a single file for entry points.

        Args:
            file_path: Path to Python file.

        Returns:
            List of entry points found in this file.
        """
        entry_points = []

        # Parse the file
        parse_result = self.python_parser.parse_file(file_path)
        if parse_result is None or parse_result.has_error:
            return []

        # Detect Flask/FastAPI routes
        entry_points.extend(self._detect_flask_routes(file_path, parse_result))
        entry_points.extend(self._detect_fastapi_routes(file_path, parse_result))

        # Detect CLI commands
        entry_points.extend(self._detect_typer_commands(file_path, parse_result))
        entry_points.extend(self._detect_click_commands(file_path, parse_result))

        # Note: User input detection (input(), stdin) would require additional
        # AST traversal not currently implemented in PythonParser

        return entry_points

    def _detect_flask_routes(self, file_path: Path, parse_result: Any) -> list[EntryPoint]:
        """Detect Flask @app.route() decorators.

        Args:
            file_path: Path to file being analyzed.
            parse_result: Parsed AST result.

        Returns:
            List of Flask route entry points.
        """
        entry_points = []

        # Iterate through functions and check their decorators
        for func in parse_result._functions:
            # Check for Flask route decorator
            for decorator_str in func.decorators:
                if "route" in decorator_str and (
                    "app" in decorator_str or "blueprint" in decorator_str
                ):
                    # Extract route path - typically first argument
                    route_path = None
                    methods = ["GET"]  # Default Flask method

                    # Simple parsing of decorator string
                    if "(" in decorator_str:
                        args_part = decorator_str.split("(", 1)[1].rsplit(")", 1)[0]
                        # Get first argument (route path)
                        if args_part:
                            first_arg = args_part.split(",")[0].strip()
                            route_path = first_arg.strip("\"'")

                            # Check for methods parameter
                            if "methods=" in args_part:
                                methods_start = args_part.index("methods=") + len("methods=")
                                methods_part = args_part[methods_start:].split("]")[0].strip("[")
                                methods = [m.strip().strip("\"'") for m in methods_part.split(",")]

                    # Check for authentication decorators
                    auth_required = any(
                        auth in dec_str
                        for dec_str in func.decorators
                        for auth in [
                            "login_required",
                            "auth_required",
                            "requires_auth",
                            "authenticated",
                        ]
                    )

                    for method in methods:
                        entry_points.append(
                            EntryPoint(
                                name=func.name,
                                type=EntryPointType.API_ENDPOINT,
                                file=file_path,
                                line=func.line_number,
                                http_method=method.upper(),
                                route=route_path,
                                auth_required=auth_required,
                                framework="Flask",
                            )
                        )

        return entry_points

    def _detect_fastapi_routes(self, file_path: Path, parse_result: Any) -> list[EntryPoint]:
        """Detect FastAPI @app.get(), @app.post(), etc. decorators.

        Args:
            file_path: Path to file being analyzed.
            parse_result: Parsed AST result.

        Returns:
            List of FastAPI route entry points.
        """
        entry_points = []

        fastapi_methods = ["get", "post", "put", "delete", "patch"]

        for func in parse_result._functions:
            for decorator_str in func.decorators:
                for method in fastapi_methods:
                    if f".{method}(" in decorator_str:
                        # Extract route path from decorator
                        route_path = None
                        if "(" in decorator_str:
                            args_part = decorator_str.split("(", 1)[1].rsplit(")", 1)[0]
                            if args_part:
                                first_arg = args_part.split(",")[0].strip()
                                route_path = first_arg.strip("\"'")

                        # Check for Depends in function arguments (FastAPI auth)
                        auth_required = any("Depends" in arg for arg in func.args)

                        entry_points.append(
                            EntryPoint(
                                name=func.name,
                                type=EntryPointType.API_ENDPOINT,
                                file=file_path,
                                line=func.line_number,
                                http_method=method.upper(),
                                route=route_path,
                                auth_required=auth_required,
                                framework="FastAPI",
                            )
                        )

        return entry_points

    def _detect_typer_commands(self, file_path: Path, parse_result: Any) -> list[EntryPoint]:
        """Detect Typer @app.command() decorators.

        Args:
            file_path: Path to file being analyzed.
            parse_result: Parsed AST result.

        Returns:
            List of Typer CLI command entry points.
        """
        entry_points = []

        for func in parse_result._functions:
            for decorator_str in func.decorators:
                if "command" in decorator_str and (
                    "app" in decorator_str or "typer" in decorator_str.lower()
                ):
                    entry_points.append(
                        EntryPoint(
                            name=func.name,
                            type=EntryPointType.CLI_COMMAND,
                            file=file_path,
                            line=func.line_number,
                            framework="Typer",
                        )
                    )

        return entry_points

    def _detect_click_commands(self, file_path: Path, parse_result: Any) -> list[EntryPoint]:
        """Detect Click @click.command() decorators.

        Args:
            file_path: Path to file being analyzed.
            parse_result: Parsed AST result.

        Returns:
            List of Click CLI command entry points.
        """
        entry_points = []

        for func in parse_result._functions:
            for decorator_str in func.decorators:
                if "click.command" in decorator_str or decorator_str.startswith("@command"):
                    entry_points.append(
                        EntryPoint(
                            name=func.name,
                            type=EntryPointType.CLI_COMMAND,
                            file=file_path,
                            line=func.line_number,
                            framework="Click",
                        )
                    )

        return entry_points

    def _detect_user_input(self, file_path: Path, parse_result: Any) -> list[EntryPoint]:
        """Detect user input via input(), stdin, etc.

        Args:
            file_path: Path to file being analyzed.
            parse_result: Parsed AST result.

        Returns:
            List of user input entry points.
        """
        entry_points = []

        # Look for input() calls
        for call in parse_result._calls:
            if call.name == "input":
                entry_points.append(
                    EntryPoint(
                        name=f"input() at line {call.line_number}",
                        type=EntryPointType.USER_INPUT,
                        file=file_path,
                        line=call.line_number,
                        framework="builtin",
                    )
                )

            # Look for sys.stdin.read(), sys.stdin.readline()
            if "stdin" in call.name and ("read" in call.name or "readline" in call.name):
                entry_points.append(
                    EntryPoint(
                        name=f"stdin at line {call.line_number}",
                        type=EntryPointType.USER_INPUT,
                        file=file_path,
                        line=call.line_number,
                        framework="builtin",
                    )
                )

        return entry_points
