"""Tests for C/C++ injection rules."""

import pytest
from hackmenot.core.scanner import Scanner


class TestCppInjectionRules:
    """Tests for C/C++ injection rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_command_injection_popen_detected(self, scanner, tmp_path):
        """Test C_INJ001 detects popen() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdio.h>

void run_command(const char* cmd) {
    FILE* fp = popen(cmd, "r");  // Command injection risk
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_INJ001"]
        assert len(findings) >= 1

    def test_sql_injection_detected(self, scanner, tmp_path):
        """Test C_INJ002 detects SQL query strings."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
void query_user(const char* user_id) {
    const char* sql = "SELECT * FROM users WHERE id = ";
    // String concatenation for SQL - injection risk
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_INJ002"]
        assert len(findings) >= 1

    def test_format_string_printf_detected(self, scanner, tmp_path):
        """Test C_INJ003 detects printf family usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdio.h>

void log_message(const char* msg) {
    printf(msg);  // Format string vulnerability if msg is user input
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_INJ003"]
        assert len(findings) >= 1

    def test_path_traversal_fopen_detected(self, scanner, tmp_path):
        """Test C_INJ004 detects fopen() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdio.h>

void open_file(const char* filename) {
    FILE* fp = fopen(filename, "r");  // Path traversal risk if filename is user input
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_INJ004"]
        assert len(findings) >= 1

    def test_clean_code_no_findings(self, scanner, tmp_path):
        """Test that safe code has no injection findings."""
        c_file = tmp_path / "safe.c"
        c_file.write_text("""
#include <string.h>

void safe_code() {
    const char* data = "safe data";
    size_t len = strlen(data);
}
""")
        result = scanner.scan([tmp_path])
        injection_findings = [f for f in result.findings if f.rule_id.startswith("C_INJ")]
        assert len(injection_findings) == 0
