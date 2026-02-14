"""Integration tests for C/C++ scanning."""

import tempfile
from pathlib import Path

from hackmenot.core.scanner import Scanner


def test_scan_c_file():
    """Test scanning a C file."""
    scanner = Scanner()

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.c"
        test_file.write_text("""
        #include <string.h>

        void copy_data(char* dest, const char* src) {
            strcpy(dest, src);  // Unsafe
        }
        """)

        result = scanner.scan([test_file])

        assert result.files_scanned == 1
        # Parser should work (findings checked in later tests)


def test_scan_cpp_file():
    """Test scanning a C++ file."""
    scanner = Scanner()

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.cpp"
        test_file.write_text("""
        #include <cstring>

        void process(char* buffer, const char* input) {
            strcpy(buffer, input);
        }
        """)

        result = scanner.scan([test_file])

        assert result.files_scanned == 1
