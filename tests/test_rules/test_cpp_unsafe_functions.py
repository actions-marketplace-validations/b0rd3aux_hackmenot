"""Tests for C/C++ unsafe function rules."""

import pytest
from hackmenot.core.scanner import Scanner


class TestCppUnsafeFunctionRules:
    """Tests for C/C++ unsafe function rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_alloca_detected(self, scanner, tmp_path):
        """Test C_FN001 detects alloca() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <alloca.h>

void create_buffer(size_t size) {
    char* buf = alloca(size);  // Unsafe stack allocation
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_FN001"]
        assert len(findings) >= 1

    def test_getenv_detected(self, scanner, tmp_path):
        """Test C_FN002 detects getenv() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdlib.h>

void load_config() {
    const char* path = getenv("CONFIG_PATH");  // Unsanitized env var
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_FN002"]
        assert len(findings) >= 1

    def test_scanf_detected(self, scanner, tmp_path):
        """Test C_FN003 detects scanf() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdio.h>

void read_input() {
    char buf[100];
    scanf("%s", buf);  // No field width limit
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_FN003"]
        assert len(findings) >= 1

    def test_system_detected(self, scanner, tmp_path):
        """Test C_FN004 detects system() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdlib.h>

void run_command(const char* cmd) {
    system(cmd);  // Command injection risk
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_FN004"]
        assert len(findings) >= 1

    def test_strncpy_detected(self, scanner, tmp_path):
        """Test C_FN005 detects strncpy() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <string.h>

void copy_string(char* dest, const char* src) {
    strncpy(dest, src, 100);  // Might not null-terminate
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_FN005"]
        assert len(findings) >= 1

    def test_strtok_detected(self, scanner, tmp_path):
        """Test C_FN006 detects strtok() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <string.h>

void split_string(char* str) {
    char* token = strtok(str, ",");  // Not thread-safe
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_FN006"]
        assert len(findings) >= 1

    def test_clean_code_no_findings(self, scanner, tmp_path):
        """Test that safe functions have no findings."""
        c_file = tmp_path / "safe.c"
        c_file.write_text("""
#include <stdio.h>
#include <string.h>

void safe_functions() {
    printf("Hello\\n");
    strlen("test");
}
""")
        result = scanner.scan([tmp_path])
        unsafe_findings = [f for f in result.findings if f.rule_id.startswith("C_FN")]
        assert len(unsafe_findings) == 0
