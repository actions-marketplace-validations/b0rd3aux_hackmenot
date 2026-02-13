"""Attack surface mapping CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from hackmenot.graph.surface import EntryPointType, SurfaceMapper

app = typer.Typer(help="Attack surface mapping and entry point detection")
console = Console()


@app.command()
def map(
    paths: list[Path] = typer.Argument(
        ...,
        help="Files or directories to analyze",
        exists=True,
    ),
    public_only: bool = typer.Option(
        False,
        "--public-only",
        help="Show only public (unauthenticated) entry points",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json",
    ),
) -> None:
    """Map the attack surface by detecting all entry points.

    Entry points are locations where untrusted data enters your application:
    - API endpoints (Flask, FastAPI routes)
    - CLI commands (Typer, Click)
    - User input (input(), stdin)
    - Webhooks and external integrations

    Example:
        hackmenot surface map . --public-only
    """
    # Map the attack surface
    mapper = SurfaceMapper()
    surface = mapper.map_surface(paths)

    # Filter if needed
    entry_points = surface.entry_points
    if public_only:
        entry_points = [ep for ep in entry_points if not ep.auth_required]

    if format == "json":
        # JSON output
        output = {
            "total_entry_points": surface.total_count,
            "public_entry_points": surface.public_count,
            "authenticated_entry_points": surface.authenticated_count,
            "entry_points": [
                {
                    "name": ep.name,
                    "type": ep.type.value,
                    "file": str(ep.file),
                    "line": ep.line,
                    "http_method": ep.http_method,
                    "route": ep.route,
                    "auth_required": ep.auth_required,
                    "framework": ep.framework,
                }
                for ep in entry_points
            ],
        }
        console.print_json(json.dumps(output, indent=2))
    else:
        # Table output
        _print_surface_table(surface, entry_points, public_only)


def _print_surface_table(surface: Any, entry_points: list[Any], public_only: bool) -> None:
    """Print attack surface as a Rich table.

    Args:
        surface: AttackSurface object with metrics.
        entry_points: List of entry points to display.
        public_only: Whether filtering for public only.
    """
    # Summary
    console.print()
    console.print("[bold]Attack Surface Summary[/bold]")
    console.print(f"  Total entry points: {surface.total_count}")
    console.print(
        f"  Public (no auth): {surface.public_count} "
        + ("[yellow]⚠️[/yellow]" if surface.public_count > 0 else "")
    )
    console.print(f"  Authenticated: {surface.authenticated_count}")
    console.print()

    if not entry_points:
        console.print("[dim]No entry points found[/dim]")
        return

    # Group by type
    by_type: dict[EntryPointType, list[Any]] = {}
    for ep in entry_points:
        if ep.type not in by_type:
            by_type[ep.type] = []
        by_type[ep.type].append(ep)

    # Print each type
    for ep_type, eps in by_type.items():
        title = f"{ep_type.value.replace('_', ' ').title()} ({len(eps)})"
        if public_only:
            title += " - Public Only"

        table = Table(title=title, show_header=True)
        table.add_column("Name", style="cyan")
        table.add_column("Location", style="dim")

        if ep_type == EntryPointType.API_ENDPOINT:
            table.add_column("Method", style="green")
            table.add_column("Route", style="yellow")
            table.add_column("Auth", style="red")
            table.add_column("Framework", style="dim")

            for ep in eps:
                table.add_row(
                    ep.name,
                    f"{ep.file.name}:{ep.line}",
                    ep.http_method or "?",
                    ep.route or "?",
                    "✓" if ep.auth_required else "[red]✗[/red]",
                    ep.framework or "?",
                )
        elif ep_type == EntryPointType.CLI_COMMAND:
            table.add_column("Framework", style="dim")

            for ep in eps:
                table.add_row(
                    ep.name,
                    f"{ep.file.name}:{ep.line}",
                    ep.framework or "?",
                )
        else:
            for ep in eps:
                table.add_row(
                    ep.name,
                    f"{ep.file.name}:{ep.line}",
                )

        console.print(table)
        console.print()
