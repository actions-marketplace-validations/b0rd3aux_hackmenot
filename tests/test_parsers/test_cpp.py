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
