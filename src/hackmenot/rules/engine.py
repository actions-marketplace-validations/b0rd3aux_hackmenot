"""Rules engine for matching patterns against parsed code."""

from pathlib import Path
from typing import Any

from hackmenot.core.models import Finding, Rule
from hackmenot.parsers.base import ParseResult
from hackmenot.parsers.golang import GoParseResult
from hackmenot.parsers.java import JavaParseResult
from hackmenot.parsers.javascript import JSParseResult
from hackmenot.parsers.rust import RustParseResult
from hackmenot.parsers.terraform import TerraformParseResult


class RulesEngine:
    """Engine for checking code against security rules."""

    def __init__(self) -> None:
        self.rules: dict[str, Rule] = {}

    def register_rule(self, rule: Rule) -> None:
        """Register a rule with the engine."""
        self.rules[rule.id] = rule

    def check(
        self,
        parse_result: ParseResult | JSParseResult,
        file_path: Path,
        ignores: set[tuple[int, str]] | None = None,
    ) -> list[Finding]:
        """Check parsed code against all registered rules.

        Args:
            parse_result: The parsed result from a parser.
            file_path: Path to the file being checked.
            ignores: Optional set of (line_number, rule_id) tuples to ignore.

        Returns:
            List of findings, excluding any that match the ignores set.
        """
        if parse_result.has_error:
            return []

        findings: list[Finding] = []
        language = self._detect_language(file_path)

        for rule in self.rules.values():
            if language not in rule.languages:
                continue

            if language == "javascript" and isinstance(parse_result, JSParseResult):
                rule_findings = self._check_js_rule(rule, parse_result, file_path)
            elif language == "go" and isinstance(parse_result, GoParseResult):
                rule_findings = self._check_go_rule(rule, parse_result, str(file_path))
            elif language == "terraform" and isinstance(parse_result, TerraformParseResult):
                rule_findings = self._check_terraform_rule(rule, parse_result, str(file_path))
            elif language == "rust" and isinstance(parse_result, RustParseResult):
                rule_findings = self._check_rust_rule(rule, parse_result, str(file_path))
            elif language == "java" and isinstance(parse_result, JavaParseResult):
                rule_findings = self._check_java_rule(rule, parse_result, str(file_path))
            else:
                rule_findings = self._check_rule(rule, parse_result, file_path)
            findings.extend(rule_findings)

        # Filter out ignored findings
        if ignores:
            findings = [f for f in findings if (f.line_number, f.rule_id) not in ignores]

        return findings

    def _detect_language(self, file_path: Path) -> str:
        """Detect language from file extension.

        Note: TypeScript is treated as JavaScript for rule matching since
        JavaScript rules apply to TypeScript files as well.
        """
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "javascript",  # TypeScript is a superset of JavaScript
            ".jsx": "javascript",
            ".tsx": "javascript",  # TSX is also treated as JavaScript
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".go": "go",
            ".tf": "terraform",
            ".tfvars": "terraform",
            ".rs": "rust",
            ".java": "java",
        }
        return ext_map.get(file_path.suffix.lower(), "unknown")

    def _check_rule(self, rule: Rule, parse_result: ParseResult, file_path: Path) -> list[Finding]:
        """Check a single rule against parsed code."""
        findings: list[Finding] = []
        pattern = rule.pattern
        pattern_type = pattern.get("type", "")

        if pattern_type == "fstring":
            findings.extend(self._check_fstring_pattern(rule, parse_result, file_path))
        elif pattern_type == "function":
            findings.extend(self._check_function_pattern(rule, parse_result, file_path))

        return findings

    def _check_fstring_pattern(
        self, rule: Rule, parse_result: ParseResult, file_path: Path
    ) -> list[Finding]:
        """Check f-string patterns."""
        findings: list[Finding] = []
        contains = rule.pattern.get("contains", [])

        for fstring in parse_result.get_fstrings():
            # Check if f-string contains any of the target strings
            if any(kw.upper() in fstring.value.upper() for kw in contains):
                # Only flag if there are interpolated variables
                if fstring.variables:
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=str(file_path),
                            line_number=fstring.line_number,
                            column=fstring.column,
                            code_snippet=f'f"{fstring.value}"',
                            fix_suggestion=rule.fix.template,
                            education=rule.education,
                        )
                    )

        return findings

    def _check_function_pattern(
        self, rule: Rule, parse_result: ParseResult, file_path: Path
    ) -> list[Finding]:
        """Check function patterns (decorators, etc.)."""
        findings: list[Finding] = []

        has_decorator = rule.pattern.get("has_decorator", [])
        missing_decorator = rule.pattern.get("missing_decorator", [])

        for func in parse_result.get_functions():
            # Check if function has required decorator
            has_target = any(any(d in dec for d in has_decorator) for dec in func.decorators)

            if has_target:
                # Check if missing security decorator
                has_security = any(
                    any(s in dec for s in missing_decorator) for dec in func.decorators
                )

                if not has_security:
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.message.format(function_name=func.name),
                            file_path=str(file_path),
                            line_number=func.line_number,
                            column=func.column,
                            code_snippet=f"def {func.name}(...):",
                            fix_suggestion=rule.fix.template,
                            education=rule.education,
                        )
                    )

        return findings

    def _check_js_rule(
        self, rule: Rule, parse_result: JSParseResult, file_path: Path
    ) -> list[Finding]:
        """Check a single rule against parsed JavaScript code."""
        findings: list[Finding] = []
        pattern = rule.pattern
        pattern_type = pattern.get("type", "")

        if pattern_type == "call":
            findings.extend(self._check_js_call_pattern(rule, parse_result, file_path))
        elif pattern_type == "string":
            findings.extend(self._check_js_string_pattern(rule, parse_result, file_path))
        elif pattern_type == "fstring":
            findings.extend(self._check_js_template_pattern(rule, parse_result, file_path))

        return findings

    def _check_js_call_pattern(
        self, rule: Rule, parse_result: JSParseResult, file_path: Path
    ) -> list[Finding]:
        """Check call patterns in JavaScript code."""
        findings: list[Finding] = []
        pattern = rule.pattern
        match_names = pattern.get("names", [])

        for call in parse_result.get_calls():
            # Check if call name matches any of the patterns
            for pattern_name in match_names:
                if pattern_name in call.name:
                    # Get source snippet for the call
                    source_snippet = f"{call.name}({', '.join(call.arguments[:2])}{'...' if len(call.arguments) > 2 else ''})"

                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=str(file_path),
                            line_number=call.line_number,
                            column=call.column,
                            code_snippet=source_snippet,
                            fix_suggestion=rule.fix.template,
                            education=rule.education,
                        )
                    )
                    break  # Only one finding per call

        return findings

    def _check_js_string_pattern(
        self, rule: Rule, parse_result: JSParseResult, file_path: Path
    ) -> list[Finding]:
        """Check string patterns in JavaScript code (template literals and assignments)."""
        findings: list[Finding] = []
        pattern = rule.pattern
        contains = pattern.get("contains", [])

        # Check template literals
        for template in parse_result.get_template_literals():
            if any(kw.upper() in template.value.upper() for kw in contains):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=rule.message,
                        file_path=str(file_path),
                        line_number=template.line_number,
                        column=template.column,
                        code_snippet=f"`{template.value[:50]}{'...' if len(template.value) > 50 else ''}`",
                        fix_suggestion=rule.fix.template,
                        education=rule.education,
                    )
                )

        # Check assignments for string values or matching assignment targets
        for assignment in parse_result.get_assignments():
            # Check if the pattern matches the assignment name (target) or value
            matches_name = any(kw in assignment.name for kw in contains)
            matches_value = assignment.value and any(
                kw.upper() in assignment.value.upper() for kw in contains
            )

            if matches_name or matches_value:
                value_preview = assignment.value[:50] if assignment.value else ""
                value_suffix = "..." if assignment.value and len(assignment.value) > 50 else ""
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=rule.message,
                        file_path=str(file_path),
                        line_number=assignment.line_number,
                        column=assignment.column,
                        code_snippet=f"{assignment.name} = {value_preview}{value_suffix}",
                        fix_suggestion=rule.fix.template,
                        education=rule.education,
                    )
                )

        # Check JSX element attributes for patterns
        for jsx_elem in parse_result.get_jsx_elements():
            for attr in jsx_elem.attributes:
                if any(kw in attr for kw in contains):
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=str(file_path),
                            line_number=jsx_elem.line_number,
                            column=jsx_elem.column,
                            code_snippet=f"<{jsx_elem.name} {attr[:50]}{'...' if len(attr) > 50 else ''}>",
                            fix_suggestion=rule.fix.template,
                            education=rule.education,
                        )
                    )

        return findings

    def _check_js_template_pattern(
        self, rule: Rule, parse_result: JSParseResult, file_path: Path
    ) -> list[Finding]:
        """Check template literal patterns with interpolation in JavaScript code."""
        findings: list[Finding] = []
        pattern = rule.pattern
        contains = pattern.get("contains", [])

        for template in parse_result.get_template_literals():
            # Only flag if template has interpolation (expressions)
            if template.expressions:
                # Check if template contains any of the target strings
                if any(kw.upper() in template.value.upper() for kw in contains):
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=str(file_path),
                            line_number=template.line_number,
                            column=template.column,
                            code_snippet=f"`{template.value[:50]}{'...' if len(template.value) > 50 else ''}`",
                            fix_suggestion=rule.fix.template,
                            education=rule.education,
                        )
                    )

        return findings

    def _create_finding(
        self,
        rule: Rule,
        file_path: str,
        line: int,
        column: int,
        code_snippet: str,
    ) -> Finding:
        """Helper to create a Finding from a rule match."""
        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            message=rule.message,
            file_path=file_path,
            line_number=line,
            column=column,
            code_snippet=code_snippet,
            fix_suggestion=rule.fix.template,
            education=rule.education,
        )

    def _check_go_rule(
        self,
        rule: Rule,
        parse_result: Any,
        file_path: str,
    ) -> list[Finding]:
        """Check a Go rule against parse result."""
        findings = []
        pattern = rule.pattern
        pattern_type = pattern.get("type", "")

        if pattern_type == "call":
            names = [n.upper() for n in pattern.get("names", [])]
            for call in parse_result.get_calls():
                if any(name in call.name.upper() for name in names):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=call.line,
                            column=call.column,
                            code_snippet=call.name,
                        )
                    )

        elif pattern_type == "string":
            contains = [c.upper() for c in pattern.get("contains", [])]
            # Check assignments
            for assign in parse_result.get_assignments():
                combined = f"{assign.target} {assign.value}".upper()
                if any(c in combined for c in contains):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=assign.line,
                            column=assign.column,
                            code_snippet=f"{assign.target} = {assign.value}",
                        )
                    )
            # Check string literals
            for string in parse_result.get_strings():
                if any(c in string.value.upper() for c in contains):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=string.line,
                            column=string.column,
                            code_snippet=string.value,
                        )
                    )

        elif pattern_type == "import":
            names = [n.lower() for n in pattern.get("names", [])]
            for imp in parse_result.get_imports():
                if any(name in imp.lower() for name in names):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=1,
                            column=0,
                            code_snippet=f'import "{imp}"',
                        )
                    )

        return findings

    def _check_rust_rule(
        self,
        rule: Rule,
        parse_result: Any,
        file_path: str,
    ) -> list[Finding]:
        """Check a Rust rule against parse result."""
        findings = []
        pattern = rule.pattern
        pattern_type = pattern.get("type", "")

        if pattern_type == "call":
            names = [n.upper() for n in pattern.get("names", [])]
            for call in parse_result.get_calls():
                if any(name in call.name.upper() for name in names):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=call.line,
                            column=call.column,
                            code_snippet=call.name,
                        )
                    )

        elif pattern_type == "macro":
            names = [n.upper() for n in pattern.get("names", [])]
            contains = [c.upper() for c in pattern.get("contains", [])]
            for macro in parse_result.get_macros():
                # Check macro name
                name_match = any(name in macro.name.upper() for name in names) if names else False
                # Check macro content for keywords
                content = " ".join(macro.args)
                contains_match = any(c in content.upper() for c in contains) if contains else False

                if name_match and (not contains or contains_match):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=macro.line,
                            column=macro.column,
                            code_snippet=f"{macro.name}(...)",
                        )
                    )

        elif pattern_type == "unsafe_block":
            for unsafe in parse_result.get_unsafe_blocks():
                findings.append(
                    self._create_finding(
                        rule=rule,
                        file_path=file_path,
                        line=unsafe.line_start,
                        column=unsafe.column,
                        code_snippet=f"unsafe {unsafe.block_type}",
                    )
                )

        elif pattern_type == "import":
            names = [n.lower() for n in pattern.get("names", [])]
            for imp in parse_result.get_imports():
                if any(name in imp.lower() for name in names):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=1,
                            column=0,
                            code_snippet=f"use {imp}",
                        )
                    )

        elif pattern_type == "string":
            contains = [c.upper() for c in pattern.get("contains", [])]
            for string in parse_result.get_strings():
                if any(c in string.value.upper() for c in contains):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=string.line,
                            column=string.column,
                            code_snippet=string.value[:50],
                        )
                    )

        elif pattern_type == "assignment":
            name_contains = [n.upper() for n in pattern.get("name_contains", [])]
            for assign in parse_result.get_assignments():
                if any(nc in assign.target.upper() for nc in name_contains):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=assign.line,
                            column=assign.column,
                            code_snippet=f"let {assign.target} = ...",
                        )
                    )

        return findings

    def _check_java_rule(
        self,
        rule: Rule,
        parse_result: Any,
        file_path: str,
    ) -> list[Finding]:
        """Check a Java rule against parse result."""
        findings = []
        pattern = rule.pattern
        pattern_type = pattern.get("type", "")

        if pattern_type == "method_invocation":
            names = [n.upper() for n in pattern.get("names", [])]
            for invocation in parse_result.get_method_invocations():
                full_name = (
                    f"{invocation.receiver}.{invocation.method_name}"
                    if invocation.receiver
                    else invocation.method_name
                )
                if any(name in full_name.upper() for name in names):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=invocation.line,
                            column=invocation.column,
                            code_snippet=f"{full_name}(...)",
                        )
                    )

        elif pattern_type == "object_creation":
            class_names = [c.upper() for c in pattern.get("class", [])]
            for creation in parse_result.get_object_creations():
                if any(cn in creation.class_name.upper() for cn in class_names):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=creation.line,
                            column=creation.column,
                            code_snippet=f"new {creation.class_name}(...)",
                        )
                    )

        elif pattern_type == "string_concat":
            contains = [c.upper() for c in pattern.get("contains", [])]
            for concat in parse_result.get_string_concats():
                if concat.in_sql_context and any(
                    c in " + ".join(concat.parts).upper() for c in contains
                ):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=concat.line,
                            column=concat.column,
                            code_snippet=" + ".join(p[:20] for p in concat.parts[:2]),
                        )
                    )

        elif pattern_type == "annotation":
            name = pattern.get("name", "").upper()
            missing = pattern.get("missing", "").upper()
            for annotation in parse_result.get_annotations():
                if name and name in annotation.name.upper():
                    # Check if missing a required annotation
                    if missing:
                        # This would need more context - simplified for now
                        pass
                    else:
                        findings.append(
                            self._create_finding(
                                rule=rule,
                                file_path=file_path,
                                line=annotation.line,
                                column=annotation.column,
                                code_snippet=f"@{annotation.name}",
                            )
                        )

        elif pattern_type == "import":
            names = [n.lower() for n in pattern.get("names", [])]
            for imp in parse_result.get_imports():
                if any(name in imp.lower() for name in names):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=1,
                            column=0,
                            code_snippet=f"import {imp}",
                        )
                    )

        elif pattern_type == "assignment":
            name_contains = [n.upper() for n in pattern.get("name_contains", [])]
            for assign in parse_result.get_assignments():
                if any(nc in assign.target.upper() for nc in name_contains):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=assign.line,
                            column=assign.column,
                            code_snippet=f"{assign.target} = ...",
                        )
                    )

        return findings

    def _check_terraform_rule(
        self,
        rule: Rule,
        parse_result: Any,
        file_path: str,
    ) -> list[Finding]:
        """Check a Terraform rule against parse result."""
        findings = []
        pattern = rule.pattern
        pattern_type = pattern.get("type", "")

        if pattern_type == "resource":
            resource_type = pattern.get("resource_type", "")
            for resource in parse_result.resources:
                if resource.resource_type != resource_type:
                    continue

                # Check field contains
                field = pattern.get("field")
                contains = pattern.get("contains", [])
                if field and contains:
                    field_value = str(resource.config.get(field, ""))
                    if any(c in field_value for c in contains):
                        findings.append(
                            self._create_finding(
                                rule=rule,
                                file_path=file_path,
                                line=resource.line,
                                column=0,
                                code_snippet=f"{resource.resource_type}.{resource.name}",
                            )
                        )

                # Check missing block
                missing_block = pattern.get("missing_block")
                if missing_block:
                    if missing_block not in resource.config:
                        findings.append(
                            self._create_finding(
                                rule=rule,
                                file_path=file_path,
                                line=resource.line,
                                column=0,
                                code_snippet=f"{resource.resource_type}.{resource.name}",
                            )
                        )

                # Check missing field with expected value
                missing_field = pattern.get("missing_field")
                expected_value = pattern.get("expected_value")
                if missing_field is not None:
                    actual = resource.config.get(missing_field)
                    if actual != expected_value:
                        findings.append(
                            self._create_finding(
                                rule=rule,
                                file_path=file_path,
                                line=resource.line,
                                column=0,
                                code_snippet=f"{resource.resource_type}.{resource.name}",
                            )
                        )

        elif pattern_type == "variable":
            name_contains = [n.lower() for n in pattern.get("name_contains", [])]
            has_default = pattern.get("has_default", False)

            for var in parse_result.variables:
                name_matches = any(c in var.name.lower() for c in name_contains)
                default_matches = has_default and var.default is not None

                if name_matches and default_matches:
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=var.line,
                            column=0,
                            code_snippet=f'variable "{var.name}"',
                        )
                    )

        elif pattern_type == "local":
            name_contains = [n.lower() for n in pattern.get("name_contains", [])]

            for local in parse_result.locals:
                if any(c in local.name.lower() for c in name_contains):
                    findings.append(
                        self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=local.line,
                            column=0,
                            code_snippet=f"local.{local.name}",
                        )
                    )

        return findings
