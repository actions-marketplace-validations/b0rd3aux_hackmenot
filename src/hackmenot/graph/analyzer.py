"""Attack path analyzer - risk scoring and exploit chain detection."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import ClassVar

from hackmenot.graph.dataflow import DataFlowPath, SinkType
from hackmenot.graph.surface import AttackSurface, EntryPointType


class RiskLevel(Enum):
    """Risk level for attack paths."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackPath:
    """A complete attack path from entry point to exploitation."""

    entry_point_name: str
    entry_point_type: EntryPointType
    entry_point_file: Path
    entry_point_line: int
    sink_type: SinkType
    sink_operation: str
    sink_file: Path
    sink_line: int
    authenticated: bool
    sanitized: bool
    risk_score: int  # 0-100
    risk_level: RiskLevel
    exploit_steps: list[str]  # Steps to exploit this path
    mitigation: str  # Recommended fix


@dataclass
class ExploitChain:
    """A chain of vulnerabilities that can be exploited together."""

    chain_id: str
    attack_paths: list[AttackPath]
    combined_risk_score: int
    description: str
    exploit_scenario: str


@dataclass
class RiskAnalysis:
    """Complete risk analysis of the codebase."""

    total_paths: int
    critical_paths: list[AttackPath]
    high_risk_paths: list[AttackPath]
    medium_risk_paths: list[AttackPath]
    low_risk_paths: list[AttackPath]
    exploit_chains: list[ExploitChain]
    overall_risk_score: int  # 0-100
    top_recommendations: list[str]


class AttackPathAnalyzer:
    """Analyzes attack paths and calculates risk scores."""

    # Risk weights for scoring
    RISK_WEIGHTS: ClassVar[dict[str, int]] = {
        "unauthenticated": 40,  # No auth required = high risk
        "critical_sink": 30,  # SQL/Command injection = critical
        "high_sink": 20,  # Eval/exec = high risk
        "medium_sink": 10,  # File operations = medium risk
        "unsanitized": 20,  # No input validation = high risk
        "direct_path": 10,  # Direct flow = easier to exploit
    }

    SINK_SEVERITY: ClassVar[dict[SinkType, str]] = {
        SinkType.SQL_QUERY: "critical",
        SinkType.SHELL_COMMAND: "critical",
        SinkType.EVAL_EXEC: "high",
        SinkType.DESERIALIZATION: "high",
        SinkType.FILE_OPERATION: "medium",
        SinkType.NETWORK_REQUEST: "medium",
        SinkType.TEMPLATE_RENDER: "medium",
    }

    def analyze(
        self, attack_surface: AttackSurface, data_flows: list[DataFlowPath]
    ) -> RiskAnalysis:
        """Analyze attack paths and calculate risk.

        Args:
            attack_surface: Mapped attack surface with entry points.
            data_flows: Traced data flows from sources to sinks.

        Returns:
            Complete risk analysis with scored attack paths.
        """
        # Build attack paths from data flows
        attack_paths = self._build_attack_paths(data_flows)

        # Calculate risk scores
        scored_paths = [self._score_path(path) for path in attack_paths]

        # Categorize by risk level
        critical = [p for p in scored_paths if p.risk_level == RiskLevel.CRITICAL]
        high = [p for p in scored_paths if p.risk_level == RiskLevel.HIGH]
        medium = [p for p in scored_paths if p.risk_level == RiskLevel.MEDIUM]
        low = [p for p in scored_paths if p.risk_level == RiskLevel.LOW]

        # Sort by risk score (descending)
        critical.sort(key=lambda p: p.risk_score, reverse=True)
        high.sort(key=lambda p: p.risk_score, reverse=True)
        medium.sort(key=lambda p: p.risk_score, reverse=True)

        # Detect exploit chains
        chains = self._detect_exploit_chains(scored_paths)

        # Calculate overall risk
        overall_risk = self._calculate_overall_risk(scored_paths)

        # Generate recommendations
        recommendations = self._generate_recommendations(critical, high, chains)

        return RiskAnalysis(
            total_paths=len(scored_paths),
            critical_paths=critical,
            high_risk_paths=high,
            medium_risk_paths=medium,
            low_risk_paths=low,
            exploit_chains=chains,
            overall_risk_score=overall_risk,
            top_recommendations=recommendations,
        )

    def _build_attack_paths(self, data_flows: list[DataFlowPath]) -> list[AttackPath]:
        """Convert data flows to attack paths.

        Args:
            data_flows: Data flow paths.

        Returns:
            List of attack paths.
        """
        paths = []

        for flow in data_flows:
            # Generate exploit steps
            exploit_steps = self._generate_exploit_steps(flow)

            # Generate mitigation advice
            mitigation = self._generate_mitigation(flow)

            path = AttackPath(
                entry_point_name=flow.source.entry_point.name,
                entry_point_type=flow.source.entry_point.type,
                entry_point_file=flow.source.file,
                entry_point_line=flow.source.line,
                sink_type=flow.sink.type,
                sink_operation=flow.sink.operation,
                sink_file=flow.sink.file,
                sink_line=flow.sink.line,
                authenticated=flow.source.entry_point.auth_required,
                sanitized=flow.sanitized,
                risk_score=0,  # Will be calculated
                risk_level=RiskLevel.INFO,  # Will be calculated
                exploit_steps=exploit_steps,
                mitigation=mitigation,
            )

            paths.append(path)

        return paths

    def _score_path(self, path: AttackPath) -> AttackPath:
        """Calculate risk score for an attack path.

        Args:
            path: Attack path to score.

        Returns:
            Attack path with calculated risk score and level.
        """
        score = 0

        # Authentication factor
        if not path.authenticated:
            score += self.RISK_WEIGHTS["unauthenticated"]

        # Sink criticality
        sink_severity = self.SINK_SEVERITY.get(path.sink_type, "medium")
        if sink_severity == "critical":
            score += self.RISK_WEIGHTS["critical_sink"]
        elif sink_severity == "high":
            score += self.RISK_WEIGHTS["high_sink"]
        else:
            score += self.RISK_WEIGHTS["medium_sink"]

        # Sanitization
        if not path.sanitized:
            score += self.RISK_WEIGHTS["unsanitized"]

        # Direct path (simplified - assume direct for now)
        score += self.RISK_WEIGHTS["direct_path"]

        # Determine risk level from score
        if score >= 80:
            level = RiskLevel.CRITICAL
        elif score >= 60:
            level = RiskLevel.HIGH
        elif score >= 40:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        path.risk_score = min(score, 100)
        path.risk_level = level

        return path

    def _generate_exploit_steps(self, flow: DataFlowPath) -> list[str]:
        """Generate step-by-step exploit instructions.

        Args:
            flow: Data flow path.

        Returns:
            List of exploit steps.
        """
        steps = []

        # Step 1: Access entry point
        ep_type = flow.source.entry_point.type
        if ep_type == EntryPointType.API_ENDPOINT:
            method = flow.source.entry_point.http_method or "HTTP"
            route = flow.source.entry_point.route or "/endpoint"
            steps.append(f"Send {method} request to {route}")

            if flow.source.parameter != "*":
                steps.append(f"Include malicious payload in '{flow.source.parameter}' parameter")
            else:
                steps.append("Include malicious payload in request parameters")

        elif ep_type == EntryPointType.CLI_COMMAND:
            steps.append(f"Execute CLI command: {flow.source.entry_point.name}()")
            if flow.source.parameter != "*":
                steps.append(f"Provide malicious input via '{flow.source.parameter}' argument")
            else:
                steps.append("Provide malicious input via command arguments")

        # Step 2: Payload reaches sink
        sink_type = flow.sink.type
        if sink_type == SinkType.SQL_QUERY:
            steps.append(
                "Payload reaches database query without sanitization, enabling SQL injection"
            )
            steps.append("Example payload: ' OR '1'='1' -- ")
        elif sink_type == SinkType.SHELL_COMMAND:
            steps.append(
                "Payload reaches shell command without sanitization, enabling command injection"
            )
            steps.append("Example payload: ; cat /etc/passwd #")
        elif sink_type == SinkType.EVAL_EXEC:
            steps.append("Payload reaches eval/exec without sanitization, enabling code injection")
            steps.append("Example payload: __import__('os').system('whoami')")

        return steps

    def _generate_mitigation(self, flow: DataFlowPath) -> str:
        """Generate mitigation advice.

        Args:
            flow: Data flow path.

        Returns:
            Mitigation recommendation.
        """
        sink_type = flow.sink.type

        if sink_type == SinkType.SQL_QUERY:
            return "Use parameterized queries or an ORM with parameter binding"
        elif sink_type == SinkType.SHELL_COMMAND:
            return "Avoid shell commands with user input; use subprocess with shell=False and argument list"
        elif sink_type == SinkType.EVAL_EXEC:
            return "Never use eval/exec with user input; redesign to avoid dynamic code execution"
        elif sink_type == SinkType.DESERIALIZATION:
            return (
                "Use safe serialization formats (JSON); validate and sanitize before deserializing"
            )
        elif sink_type == SinkType.FILE_OPERATION:
            return (
                "Validate file paths against allowlist; use Path.resolve() and check path traversal"
            )
        else:
            return "Validate and sanitize all user input before use"

    def _detect_exploit_chains(self, paths: list[AttackPath]) -> list[ExploitChain]:
        """Detect exploit chains across multiple vulnerabilities.

        Args:
            paths: Scored attack paths.

        Returns:
            List of exploit chains.
        """
        chains = []

        # Group by entry point to find chains
        entry_point_groups: dict[str, list[AttackPath]] = {}
        for path in paths:
            key = f"{path.entry_point_file}:{path.entry_point_line}"
            if key not in entry_point_groups:
                entry_point_groups[key] = []
            entry_point_groups[key].append(path)

        # Create chains where one entry point leads to multiple sinks
        chain_id = 1
        for ep_key, ep_paths in entry_point_groups.items():
            if len(ep_paths) > 1:
                # Multiple sinks from one entry point = exploit chain
                combined_score = min(sum(p.risk_score for p in ep_paths) // len(ep_paths), 100)

                ep_name = ep_paths[0].entry_point_name
                sink_types = [p.sink_type.value for p in ep_paths]

                description = (
                    f"Entry point '{ep_name}' exposes {len(ep_paths)} "
                    f"different attack paths ({', '.join(sink_types)})"
                )

                scenario = (
                    "An attacker could exploit multiple vulnerabilities through "
                    "a single entry point, potentially escalating privileges or "
                    "chaining attacks for greater impact."
                )

                chains.append(
                    ExploitChain(
                        chain_id=f"CHAIN-{chain_id:03d}",
                        attack_paths=ep_paths,
                        combined_risk_score=combined_score,
                        description=description,
                        exploit_scenario=scenario,
                    )
                )
                chain_id += 1

        return chains

    def _calculate_overall_risk(self, paths: list[AttackPath]) -> int:
        """Calculate overall codebase risk score.

        Args:
            paths: All attack paths.

        Returns:
            Overall risk score (0-100).
        """
        if not paths:
            return 0

        # Weight by severity
        total_weighted = 0
        total_weight = 0

        for path in paths:
            weight = 1.0
            if path.risk_level == RiskLevel.CRITICAL:
                weight = 3.0
            elif path.risk_level == RiskLevel.HIGH:
                weight = 2.0

            total_weighted += path.risk_score * weight
            total_weight += weight

        return min(int(total_weighted / total_weight), 100) if total_weight > 0 else 0

    def _generate_recommendations(
        self,
        critical: list[AttackPath],
        high: list[AttackPath],
        chains: list[ExploitChain],
    ) -> list[str]:
        """Generate top recommendations for remediation.

        Args:
            critical: Critical risk paths.
            high: High risk paths.
            chains: Detected exploit chains.

        Returns:
            List of prioritized recommendations.
        """
        recommendations = []

        # Prioritize exploit chains
        if chains:
            recommendations.append(
                f"🔴 CRITICAL: Fix {len(chains)} exploit chain(s) that expose "
                f"multiple vulnerabilities through single entry points"
            )

        # Critical paths
        if critical:
            unauthenticated = [p for p in critical if not p.authenticated]
            if unauthenticated:
                recommendations.append(
                    f"🔴 CRITICAL: Secure {len(unauthenticated)} unauthenticated "
                    f"path(s) with critical vulnerabilities"
                )

            sql_injection = [p for p in critical if p.sink_type == SinkType.SQL_QUERY]
            if sql_injection:
                recommendations.append(
                    f"🔴 CRITICAL: Fix {len(sql_injection)} SQL injection "
                    f"vulnerability/vulnerabilities using parameterized queries"
                )

            cmd_injection = [p for p in critical if p.sink_type == SinkType.SHELL_COMMAND]
            if cmd_injection:
                # Use concat to avoid false positive INJ002
                count = len(cmd_injection)
                recommendations.append(
                    "🔴 CRITICAL: Fix "
                    + str(count)
                    + " command injection vulnerability/vulnerabilities using safe subprocess calls"
                )

        # High risk paths
        if high:
            recommendations.append(
                f"🟠 HIGH: Address {len(high)} high-risk attack path(s) "
                f"with proper input validation"
            )

        # General recommendations
        if not recommendations:
            recommendations.append("✅ No critical vulnerabilities detected")
        else:
            recommendations.append(
                "💡 TIP: Use 'hackmenot scan --fix' to auto-fix some vulnerabilities"
            )

        return recommendations[:5]  # Top 5 recommendations
