"""Security graph builder - generate GraphViz DOT visualization."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from hackmenot.graph.dataflow import DataFlowTracker, SinkType
from hackmenot.graph.surface import EntryPointType, SurfaceMapper


@dataclass
class GraphNode:
    """A node in the security graph."""

    id: str  # Unique identifier
    label: str  # Display label
    type: str  # "entry_point", "function", "sink"
    risk_level: str | None = None  # "critical", "high", "medium", "low"
    file: Path | None = None
    line: int | None = None
    metadata: dict[str, str] | None = None


@dataclass
class GraphEdge:
    """An edge in the security graph."""

    source: str  # Source node ID
    target: str  # Target node ID
    label: str | None = None
    type: str = "call"  # "call", "dataflow"
    is_vulnerable: bool = False


class SecurityGraphBuilder:
    """Builds security graph from attack surface and data flows."""

    def __init__(self) -> None:
        """Initialize the graph builder."""
        self.surface_mapper = SurfaceMapper()
        self.flow_tracker = DataFlowTracker()
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []

    def build(self, paths: list[Path]) -> None:
        """Build security graph from files.

        Args:
            paths: Files or directories to analyze.
        """
        # Clear previous graph
        self.nodes = []
        self.edges = []

        # 1. Map attack surface
        attack_surface = self.surface_mapper.map_surface(paths)

        # 2. Analyze data flows
        flows = self.flow_tracker.analyze(paths)

        # 3. Build nodes
        self._add_entry_point_nodes(attack_surface.entry_points)
        self._add_sink_nodes(flows)

        # 4. Build edges
        self._add_flow_edges(flows)

    def _add_entry_point_nodes(self, entry_points: list) -> None:
        """Add entry point nodes to graph.

        Args:
            entry_points: List of entry points.
        """
        for ep in entry_points:
            node_id = f"ep_{ep.name}_{ep.line}"
            label = self._format_entry_point_label(ep)

            # Determine risk level based on authentication
            risk_level = "high" if not ep.auth_required else "medium"

            self.nodes.append(
                GraphNode(
                    id=node_id,
                    label=label,
                    type="entry_point",
                    risk_level=risk_level,
                    file=ep.file,
                    line=ep.line,
                    metadata={
                        "entry_type": ep.type.value,
                        "auth_required": str(ep.auth_required),
                        "framework": ep.framework or "unknown",
                    },
                )
            )

    def _add_sink_nodes(self, flows: list) -> None:
        """Add security sink nodes to graph.

        Args:
            flows: List of data flow paths.
        """
        seen_sinks = set()

        for flow in flows:
            sink = flow.sink
            sink_id = f"sink_{sink.file.name}_{sink.line}"

            if sink_id not in seen_sinks:
                seen_sinks.add(sink_id)
                label = self._format_sink_label(sink)

                # Sinks are always high risk
                risk_level = "critical"

                self.nodes.append(
                    GraphNode(
                        id=sink_id,
                        label=label,
                        type="sink",
                        risk_level=risk_level,
                        file=sink.file,
                        line=sink.line,
                        metadata={
                            "sink_type": sink.type.value,
                            "operation": sink.operation,
                        },
                    )
                )

    def _add_flow_edges(self, flows: list) -> None:
        """Add data flow edges to graph.

        Args:
            flows: List of data flow paths.
        """
        for flow in flows:
            source_id = f"ep_{flow.source.entry_point.name}_{flow.source.line}"
            sink_id = f"sink_{flow.sink.file.name}_{flow.sink.line}"

            # Create edge from entry point to sink
            self.edges.append(
                GraphEdge(
                    source=source_id,
                    target=sink_id,
                    label=flow.source.parameter,
                    type="dataflow",
                    is_vulnerable=not flow.sanitized,
                )
            )

    def _format_entry_point_label(self, ep) -> str:
        """Format entry point label for display.

        Args:
            ep: Entry point object.

        Returns:
            Formatted label string.
        """
        if ep.type == EntryPointType.API_ENDPOINT:
            method = ep.http_method or "?"
            route = ep.route or "?"
            auth = "🔒" if ep.auth_required else "🔓"
            return f"{auth} {method} {route}\\n{ep.name}()"
        elif ep.type == EntryPointType.CLI_COMMAND:
            return f"⌨️  {ep.name}()\\n[CLI Command]"
        else:
            return f"{ep.name}()\\n[{ep.type.value}]"

    def _format_sink_label(self, sink) -> str:
        """Format sink label for display.

        Args:
            sink: Taint sink object.

        Returns:
            Formatted label string.
        """
        type_emoji = {
            SinkType.SQL_QUERY: "💾",
            SinkType.SHELL_COMMAND: "💻",
            SinkType.EVAL_EXEC: "⚠️",
        }
        emoji = type_emoji.get(sink.type, "🔴")
        type_name = sink.type.value.replace("_", " ").title()
        return f"{emoji} {type_name}\\n{sink.operation}"

    def _escape_label(self, label: str) -> str:
        """Escape special characters in GraphViz labels.

        Args:
            label: Raw label string.

        Returns:
            Escaped label safe for DOT format.
        """
        # Replace angle brackets to avoid HTML parsing issues
        return label.replace("<", "[").replace(">", "]")

    def to_dot(self) -> str:
        """Generate GraphViz DOT format output with modern styling.

        Returns:
            DOT format string with beautiful modern design.
        """
        lines = []

        # Modern graph settings with enhanced visual design
        lines.append("digraph security_graph {")
        lines.append("  // Modern styling configuration")
        lines.append("  graph [")
        lines.append('    bgcolor="#1a1d2e",')
        lines.append('    fontname="Helvetica Neue,Helvetica,Arial,sans-serif",')
        lines.append("    fontsize=14,")
        lines.append("    rankdir=LR,")
        lines.append("    splines=curved,")
        lines.append("    nodesep=1.2,")
        lines.append("    ranksep=1.8,")
        lines.append("    pad=0.5")
        lines.append("  ];")
        lines.append("")

        # Modern node defaults
        lines.append("  node [")
        lines.append('    fontname="Helvetica Neue,Helvetica,Arial,sans-serif",')
        lines.append("    fontsize=11,")
        lines.append('    fontcolor="#ffffff",')
        lines.append('    style="filled,rounded",')
        lines.append("    penwidth=2,")
        lines.append("    margin=0.3")
        lines.append("  ];")
        lines.append("")

        # Modern edge defaults
        lines.append("  edge [")
        lines.append('    fontname="Helvetica Neue,Helvetica,Arial,sans-serif",')
        lines.append("    fontsize=9,")
        lines.append('    fontcolor="#95a5a6",')
        lines.append("    penwidth=2.5,")
        lines.append("    arrowsize=1.2")
        lines.append("  ];")
        lines.append("")

        # Add entry point nodes with modern design
        lines.append("  // Entry Points - Modern Design")
        for node in self.nodes:
            if node.type == "entry_point":
                escaped_label = self._escape_label(node.label)

                # Determine colors based on risk
                if node.risk_level == "critical":
                    fillcolor = "#e74c3c:#c0392b"  # Red gradient
                    color = "#c0392b"
                elif node.risk_level == "high":
                    fillcolor = "#e67e22:#d35400"  # Orange gradient
                    color = "#d35400"
                else:
                    fillcolor = "#f39c12:#e67e22"  # Yellow-orange gradient
                    color = "#e67e22"

                node_def = (
                    f'  "{node.id}" ['
                    f'label="{escaped_label}", '
                    f'fillcolor="{fillcolor}", '
                    f'color="{color}", '
                    "shape=box, "
                    'style="filled,rounded,bold"'
                    "];"
                )
                lines.append(node_def)

        lines.append("")
        lines.append("  // Security Sinks - Modern Design")
        for node in self.nodes:
            if node.type == "sink":
                escaped_label = self._escape_label(node.label)

                # All sinks are critical - use red gradient
                fillcolor = "#e74c3c:#c0392b"
                color = "#c0392b"

                node_def = (
                    f'  "{node.id}" ['
                    f'label="{escaped_label}", '
                    f'fillcolor="{fillcolor}", '
                    f'color="{color}", '
                    "shape=ellipse, "
                    'style="filled,bold"'
                    "];"
                )
                lines.append(node_def)

        lines.append("")
        lines.append("  // Data Flows - Modern Arrows")
        for edge in self.edges:
            if edge.is_vulnerable:
                # Vulnerable path - bright red
                color = "#e74c3c"
                style = "bold,dashed"
                penwidth = "3.5"
            else:
                # Safe path - green
                color = "#2ecc71"
                style = "solid"
                penwidth = "2.0"

            label = edge.label or ""

            edge_def = (
                f'  "{edge.source}" -> "{edge.target}" ['
                f'label="{label}", '
                f'color="{color}", '
                f'style="{style}", '
                f"penwidth={penwidth}, "
                "arrowhead=vee"
                "];"
            )
            lines.append(edge_def)

        lines.append("}")
        return "\n".join(lines)

    def write_dot(self, output: Path | TextIO) -> None:
        """Write DOT format to file or stream.

        Args:
            output: File path or text stream to write to.
        """
        dot_content = self.to_dot()

        if isinstance(output, Path):
            output.write_text(dot_content)
        else:
            output.write(dot_content)

    def _get_node_color(self, risk_level: str | None) -> str:
        """Get color for node based on risk level.

        Args:
            risk_level: Risk level string.

        Returns:
            Color name or hex code.
        """
        colors = {
            "critical": "lightcoral",
            "high": "lightsalmon",
            "medium": "lightyellow",
            "low": "lightgreen",
        }
        return colors.get(risk_level or "medium", "lightgray")

    def get_stats(self) -> dict[str, int]:
        """Get graph statistics.

        Returns:
            Dictionary with node and edge counts.
        """
        return {
            "total_nodes": len(self.nodes),
            "entry_points": sum(1 for n in self.nodes if n.type == "entry_point"),
            "sinks": sum(1 for n in self.nodes if n.type == "sink"),
            "total_edges": len(self.edges),
            "vulnerable_flows": sum(1 for e in self.edges if e.is_vulnerable),
        }
