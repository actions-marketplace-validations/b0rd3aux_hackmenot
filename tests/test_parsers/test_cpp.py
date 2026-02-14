"""Tests for C/C++ parser."""

from pathlib import Path

from hackmenot.parsers.cpp import CppCallInfo


def test_cpp_call_info_creation():
    """Test CppCallInfo dataclass."""
    call = CppCallInfo(name="strcpy", args=["dest", "src"], line=10, column=5)
    assert call.name == "strcpy"
    assert call.args == ["dest", "src"]
    assert call.line == 10
    assert call.column == 5


def test_parse_simple_c_code():
    """Test parsing simple C code."""
    from hackmenot.parsers.cpp import CppParser

    parser = CppParser()
    source = """
    #include <stdio.h>

    int main() {
        printf("Hello, World!");
        return 0;
    }
    """

    result = parser.parse_string(source, "test.c")

    assert not result.has_error
    assert result.file_path == Path("test.c")
    # Should detect printf call
    calls = result.get_calls()
    assert len(calls) > 0
    assert any(c.name == "printf" for c in calls)


def test_parse_strcpy_call():
    """Test detecting strcpy calls."""
    from hackmenot.parsers.cpp import CppParser

    parser = CppParser()
    source = """
    void copy_data(char* dest, const char* src) {
        strcpy(dest, src);
    }
    """

    result = parser.parse_string(source, "test.c")

    assert not result.has_error
    calls = result.get_calls()
    strcpy_calls = [c for c in calls if c.name == "strcpy"]
    assert len(strcpy_calls) == 1
    assert strcpy_calls[0].args == ["dest", "src"]


def test_parse_include_statements():
    """Test extracting #include statements."""
    from hackmenot.parsers.cpp import CppParser

    parser = CppParser()
    source = """
    #include <stdio.h>
    #include <string.h>
    #include "custom.h"
    """

    result = parser.parse_string(source, "test.c")

    includes = result.get_includes()
    assert len(includes) == 3
    assert "<stdio.h>" in includes
    assert "<string.h>" in includes
    assert '"custom.h"' in includes


def test_parse_format_strings():
    """Test detecting format strings."""
    from hackmenot.parsers.cpp import CppParser

    parser = CppParser()
    source = """
    void log_message(int code) {
        printf("Error code: %d\\n", code);
    }
    """

    result = parser.parse_string(source, "test.c")

    strings = result.get_strings()
    format_strings = [s for s in strings if s.is_format_string]
    assert len(format_strings) > 0


def test_parse_error_handling():
    """Test parser handles syntax errors."""
    from hackmenot.parsers.cpp import CppParser

    parser = CppParser()
    source = """
    void broken( {
        // Missing closing brace
    """

    result = parser.parse_string(source, "test.c")

    assert result.has_error
    assert "Syntax errors" in result.error_message


def test_parse_empty_file():
    """Test parser handles empty files."""
    from hackmenot.parsers.cpp import CppParser

    parser = CppParser()
    result = parser.parse_string("", "test.c")

    assert not result.has_error
    assert len(result.get_calls()) == 0
