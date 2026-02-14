"""Tests for C/C++ memory safety rules."""

import pytest
from hackmenot.core.models import Severity
from hackmenot.core.scanner import Scanner


class TestCppMemorySafetyRules:
    """Tests for C/C++ memory safety rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_strcpy_detected(self, scanner, tmp_path):
        """Test C_MEM001 detects unsafe strcpy usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <string.h>

void copy_data(char* dest, const char* src) {
    strcpy(dest, src);  // Vulnerable
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_MEM001"]
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_strcpy_in_cpp_detected(self, scanner, tmp_path):
        """Test C_MEM001 detects strcpy in C++ code."""
        cpp_file = tmp_path / "test.cpp"
        cpp_file.write_text("""
#include <cstring>

void unsafe_copy(char* dest, const char* src) {
    strcpy(dest, src);  // Vulnerable
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_MEM001"]
        assert len(findings) >= 1

    def test_strcat_detected(self, scanner, tmp_path):
        """Test C_MEM002 detects unsafe strcat usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <string.h>

void append_data(char* dest, const char* src) {
    strcat(dest, src);  // Vulnerable
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_MEM002"]
        assert len(findings) >= 1

    def test_use_after_free_detected(self, scanner, tmp_path):
        """Test C_MEM003 detects free() calls (potential use-after-free)."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdlib.h>

void risky_free(char* ptr) {
    free(ptr);  // Potential use-after-free if not careful
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_MEM003"]
        assert len(findings) >= 1

    def test_double_free_detected(self, scanner, tmp_path):
        """Test C_MEM004 detects free() calls (potential double-free)."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdlib.h>

void unsafe_cleanup(char* ptr) {
    free(ptr);  // Could be called twice
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_MEM004"]
        assert len(findings) >= 1

    def test_null_deref_malloc_detected(self, scanner, tmp_path):
        """Test C_MEM005 detects malloc without NULL check."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdlib.h>

void allocate_buffer(size_t size) {
    char* buf = malloc(size);  // Should check for NULL
    *buf = 'A';
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_MEM005"]
        assert len(findings) >= 1

    def test_memory_leak_detected(self, scanner, tmp_path):
        """Test C_MEM006 detects malloc (potential leak)."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdlib.h>

void create_buffer() {
    char* buf = malloc(100);  // Might not be freed
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_MEM006"]
        assert len(findings) >= 1

    def test_stack_overflow_gets_detected(self, scanner, tmp_path):
        """Test C_MEM007 detects gets() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdio.h>

void read_input() {
    char buf[100];
    gets(buf);  // Dangerous stack overflow
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_MEM007"]
        assert len(findings) >= 1

    def test_stack_overflow_sprintf_detected(self, scanner, tmp_path):
        """Test C_MEM007 detects sprintf() usage."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdio.h>

void format_string(const char* input) {
    char buf[100];
    sprintf(buf, "%s", input);  // Stack overflow risk
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_MEM007"]
        assert len(findings) >= 1

    # Note: C_MEM008 (Dangling Pointer) detection requires more sophisticated
    # static analysis than simple pattern matching. Skipping for now.

    def test_clean_code_no_findings(self, scanner, tmp_path):
        """Test that safe string operations have no findings."""
        c_file = tmp_path / "safe.c"
        c_file.write_text("""
#include <stdio.h>
#include <string.h>

void safe_copy(char* dest, const char* src, size_t dest_size) {
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\\0';
}

int main() {
    printf("Hello, World!\\n");
    return 0;
}
""")
        result = scanner.scan([tmp_path])
        mem_findings = [f for f in result.findings if f.rule_id.startswith("C_MEM")]
        assert len(mem_findings) == 0
