"""Tests for C/C++ integer issue rules."""

import pytest
from hackmenot.core.scanner import Scanner


class TestCppIntegerIssueRules:
    """Tests for C/C++ integer issue rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_signedness_error_read_detected(self, scanner, tmp_path):
        """Test C_INT003 detects read() (signedness risk)."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <unistd.h>

void read_data(int fd, char* buf) {
    ssize_t bytes = read(fd, buf, 100);  // Returns signed, often used unsigned
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_INT003"]
        assert len(findings) >= 1

    def test_signedness_error_recv_detected(self, scanner, tmp_path):
        """Test C_INT003 detects recv() (signedness risk)."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <sys/socket.h>

void receive_data(int sockfd, char* buf) {
    ssize_t bytes = recv(sockfd, buf, 100, 0);  // Returns signed
}
""")
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "C_INT003"]
        assert len(findings) >= 1

    def test_clean_code_no_findings(self, scanner, tmp_path):
        """Test that simple code has no integer issue findings."""
        c_file = tmp_path / "safe.c"
        c_file.write_text("""
void simple_function(int x, int y) {
    int sum = x + y;
}
""")
        result = scanner.scan([tmp_path])
        int_findings = [f for f in result.findings if f.rule_id.startswith("C_INT")]
        assert len(int_findings) == 0
