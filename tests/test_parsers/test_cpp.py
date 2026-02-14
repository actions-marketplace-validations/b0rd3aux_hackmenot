"""Tests for C/C++ parser."""

from hackmenot.parsers.cpp import CppCallInfo


def test_cpp_call_info_creation():
    """Test CppCallInfo dataclass."""
    call = CppCallInfo(name="strcpy", args=["dest", "src"], line=10, column=5)
    assert call.name == "strcpy"
    assert call.args == ["dest", "src"]
    assert call.line == 10
    assert call.column == 5
