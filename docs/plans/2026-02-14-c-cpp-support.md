# C/C++ Language Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add comprehensive C/C++ security scanning with 20-30 rules covering memory safety, injection flaws, integer issues, and unsafe functions.

**Architecture:** Single CppParser using tree-sitter-cpp for both C and C++ files, following the existing parser pattern (JavaScript handles both JS and TS). Detects function calls, unsafe functions, pointer operations, arrays, strings, and integer operations. Rules organized in c-cpp/ directory with YAML format.

**Tech Stack:** Python 3.10+, tree-sitter-cpp, pytest, existing hackmenot architecture

**Design Document:** `docs/plans/2026-02-14-c-cpp-support-design.md`

---

## Phase 1: Parser Foundation (Days 1-2)

### Task 1: Add tree-sitter-cpp Dependency

**Files:**
- Modify: `pyproject.toml:29-40`

**Step 1: Add dependency to pyproject.toml**

```toml
dependencies = [
    "typer>=0.9.0",
    "rich>=13.0.0",
    "pyyaml>=6.0",
    "tree-sitter>=0.23.0",
    "tree-sitter-javascript>=0.23.0",
    "tree-sitter-go>=0.21.0",
    "tree-sitter-rust>=0.23.0",
    "tree-sitter-java>=0.23.5",
    "tree-sitter-cpp>=0.20.0",  # New
    "python-hcl2>=4.3.0",
    "tqdm>=4.66.0",
]
```

**Step 2: Install dependency**

Run: `pip install -e ".[dev]"`
Expected: tree-sitter-cpp installed successfully

**Step 3: Verify import**

Run: `python -c "import tree_sitter_cpp as ts_cpp; print('OK')"`
Expected: "OK"

**Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "build: add tree-sitter-cpp dependency"
```

---

### Task 2: Create CppParser Info Dataclasses

**Files:**
- Create: `src/hackmenot/parsers/cpp.py`

**Step 1: Write test for CppCallInfo dataclass**

Create: `tests/test_parsers/test_cpp.py`

```python
"""Tests for C/C++ parser."""

from pathlib import Path
from hackmenot.parsers.cpp import CppCallInfo, CppParseResult


def test_cpp_call_info_creation():
    """Test CppCallInfo dataclass."""
    call = CppCallInfo(
        name="strcpy",
        args=["dest", "src"],
        line=10,
        column=5
    )
    assert call.name == "strcpy"
    assert call.args == ["dest", "src"]
    assert call.line == 10
    assert call.column == 5
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_parsers/test_cpp.py::test_cpp_call_info_creation -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'hackmenot.parsers.cpp'"

**Step 3: Create cpp.py with dataclasses**

Create: `src/hackmenot/parsers/cpp.py`

```python
"""C/C++ parser using tree-sitter."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter_cpp as ts_cpp
from tree_sitter import Language, Node, Parser

from hackmenot.parsers.base import BaseParser


@dataclass
class CppCallInfo:
    """Information about a function/method call in C/C++."""

    name: str
    args: list[str] = field(default_factory=list)
    line: int = 0
    column: int = 0


@dataclass
class CppUnsafeFunctionInfo:
    """Information about an unsafe function usage."""

    name: str
    args: list[str] = field(default_factory=list)
    has_size_check: bool = False
    line: int = 0
    column: int = 0


@dataclass
class CppPointerInfo:
    """Information about pointer operations."""

    operation: str  # "dereference", "arithmetic", "cast"
    expression: str
    line: int = 0
    column: int = 0


@dataclass
class CppArrayInfo:
    """Information about array access."""

    name: str
    index_expr: str
    is_fixed_size: bool = False
    size: int | None = None
    line: int = 0
    column: int = 0


@dataclass
class CppStringInfo:
    """Information about string literals."""

    value: str
    is_format_string: bool = False
    line: int = 0
    column: int = 0


@dataclass
class CppParseResult:
    """Result of parsing a C/C++ file."""

    file_path: Path = field(default_factory=lambda: Path("<string>"))
    has_error: bool = False
    error_message: str | None = None
    _calls: list[CppCallInfo] = field(default_factory=list)
    _unsafe_functions: list[CppUnsafeFunctionInfo] = field(default_factory=list)
    _pointers: list[CppPointerInfo] = field(default_factory=list)
    _arrays: list[CppArrayInfo] = field(default_factory=list)
    _strings: list[CppStringInfo] = field(default_factory=list)
    _includes: list[str] = field(default_factory=list)
    _raw_tree: Any = None

    def get_calls(self) -> list[CppCallInfo]:
        """Get all function/method calls."""
        return self._calls

    def get_unsafe_functions(self) -> list[CppUnsafeFunctionInfo]:
        """Get all unsafe function usages."""
        return self._unsafe_functions

    def get_pointers(self) -> list[CppPointerInfo]:
        """Get all pointer operations."""
        return self._pointers

    def get_arrays(self) -> list[CppArrayInfo]:
        """Get all array accesses."""
        return self._arrays

    def get_strings(self) -> list[CppStringInfo]:
        """Get all string literals."""
        return self._strings

    def get_includes(self) -> list[str]:
        """Get all include statements."""
        return self._includes
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_parsers/test_cpp.py::test_cpp_call_info_creation -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/hackmenot/parsers/cpp.py tests/test_parsers/test_cpp.py
git commit -m "feat(parser): add C/C++ parser dataclasses"
```

---

### Task 3: Implement CppParser parse_string Method

**Files:**
- Modify: `src/hackmenot/parsers/cpp.py`
- Modify: `tests/test_parsers/test_cpp.py`

**Step 1: Write failing test for parse_string**

Add to: `tests/test_parsers/test_cpp.py`

```python
def test_parse_simple_c_code():
    """Test parsing simple C code."""
    from hackmenot.parsers.cpp import CppParser

    parser = CppParser()
    source = '''
    #include <stdio.h>

    int main() {
        printf("Hello, World!");
        return 0;
    }
    '''

    result = parser.parse_string(source, "test.c")

    assert not result.has_error
    assert result.file_path == Path("test.c")
    # Should detect printf call
    calls = result.get_calls()
    assert len(calls) > 0
    assert any(c.name == "printf" for c in calls)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_parsers/test_cpp.py::test_parse_simple_c_code -v`
Expected: FAIL with "AttributeError: 'CppParser' object has no attribute 'parse_string'"

**Step 3: Implement CppParser class**

Add to: `src/hackmenot/parsers/cpp.py`

```python
class CppParser(BaseParser):
    """C/C++ parser using tree-sitter-cpp."""

    def __init__(self):
        """Initialize C/C++ parser."""
        self.language = Language(ts_cpp.language())
        self.parser = Parser(self.language)

    def parse_file(self, file_path: Path) -> CppParseResult:
        """Parse a C/C++ file from disk."""
        try:
            source = file_path.read_text(encoding="utf-8")
            return self.parse_string(source, str(file_path))
        except UnicodeDecodeError:
            return CppParseResult(
                file_path=file_path,
                has_error=True,
                error_message="File is not valid UTF-8"
            )
        except OSError as e:
            return CppParseResult(
                file_path=file_path,
                has_error=True,
                error_message=f"Could not read file: {e}"
            )

    def parse_string(self, source: str, filename: str = "<string>") -> CppParseResult:
        """Parse C/C++ source code string."""
        try:
            tree = self.parser.parse(bytes(source, "utf-8"))

            if self._has_syntax_errors(tree.root_node):
                return CppParseResult(
                    file_path=Path(filename),
                    has_error=True,
                    error_message="Syntax errors in C/C++ code"
                )

            # Extract patterns
            calls = self._extract_calls(tree.root_node)
            includes = self._extract_includes(tree.root_node)
            strings = self._extract_strings(tree.root_node)

            return CppParseResult(
                file_path=Path(filename),
                _calls=calls,
                _includes=includes,
                _strings=strings,
                _raw_tree=tree
            )

        except Exception as e:
            return CppParseResult(
                file_path=Path(filename),
                has_error=True,
                error_message=f"Parser error: {e}"
            )

    def _has_syntax_errors(self, node: Node) -> bool:
        """Check if tree has syntax errors."""
        if node.type == "ERROR":
            return True
        for child in node.children:
            if self._has_syntax_errors(child):
                return True
        return False

    def _extract_calls(self, node: Node) -> list[CppCallInfo]:
        """Extract function calls from AST."""
        calls: list[CppCallInfo] = []

        def visit(n: Node):
            if n.type == "call_expression":
                # Get function name
                func_node = n.child_by_field_name("function")
                if func_node:
                    func_name = func_node.text.decode("utf-8") if func_node.text else ""

                    # Get arguments
                    args_node = n.child_by_field_name("arguments")
                    args = []
                    if args_node:
                        for arg in args_node.children:
                            if arg.type != "," and arg.type != "(" and arg.type != ")":
                                args.append(arg.text.decode("utf-8") if arg.text else "")

                    calls.append(CppCallInfo(
                        name=func_name,
                        args=args,
                        line=n.start_point[0] + 1,
                        column=n.start_point[1]
                    ))

            for child in n.children:
                visit(child)

        visit(node)
        return calls

    def _extract_includes(self, node: Node) -> list[str]:
        """Extract #include statements."""
        includes: list[str] = []

        def visit(n: Node):
            if n.type == "preproc_include":
                path_node = n.child_by_field_name("path")
                if path_node and path_node.text:
                    includes.append(path_node.text.decode("utf-8"))

            for child in n.children:
                visit(child)

        visit(node)
        return includes

    def _extract_strings(self, node: Node) -> list[CppStringInfo]:
        """Extract string literals."""
        strings: list[CppStringInfo] = []

        def visit(n: Node):
            if n.type == "string_literal":
                value = n.text.decode("utf-8") if n.text else ""
                # Check if it's a format string (contains %)
                is_format = "%" in value

                strings.append(CppStringInfo(
                    value=value,
                    is_format_string=is_format,
                    line=n.start_point[0] + 1,
                    column=n.start_point[1]
                ))

            for child in n.children:
                visit(child)

        visit(node)
        return strings
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_parsers/test_cpp.py::test_parse_simple_c_code -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/hackmenot/parsers/cpp.py tests/test_parsers/test_cpp.py
git commit -m "feat(parser): implement CppParser parse_string method"
```

---

### Task 4: Add More Parser Tests

**Files:**
- Modify: `tests/test_parsers/test_cpp.py`

**Step 1: Write test for strcpy detection**

Add to: `tests/test_parsers/test_cpp.py`

```python
def test_parse_strcpy_call():
    """Test detecting strcpy calls."""
    from hackmenot.parsers.cpp import CppParser

    parser = CppParser()
    source = '''
    void copy_data(char* dest, const char* src) {
        strcpy(dest, src);
    }
    '''

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
    source = '''
    #include <stdio.h>
    #include <string.h>
    #include "custom.h"
    '''

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
    source = '''
    void log_message(int code) {
        printf("Error code: %d\\n", code);
    }
    '''

    result = parser.parse_string(source, "test.c")

    strings = result.get_strings()
    format_strings = [s for s in strings if s.is_format_string]
    assert len(format_strings) > 0


def test_parse_error_handling():
    """Test parser handles syntax errors."""
    from hackmenot.parsers.cpp import CppParser

    parser = CppParser()
    source = '''
    void broken( {
        // Missing closing brace
    '''

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
```

**Step 2: Run tests**

Run: `pytest tests/test_parsers/test_cpp.py -v`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add tests/test_parsers/test_cpp.py
git commit -m "test(parser): add comprehensive C/C++ parser tests"
```

---

## Phase 2: Scanner Integration (Day 3)

### Task 5: Add C/C++ Extensions to Constants

**Files:**
- Modify: `src/hackmenot/core/constants.py:11-27`

**Step 1: Add C/C++ extensions**

```python
# File extension sets by language
PYTHON_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
GO_EXTENSIONS = {".go"}
TERRAFORM_EXTENSIONS = {".tf", ".tfvars"}
RUST_EXTENSIONS = {".rs"}
JAVA_EXTENSIONS = {".java"}
C_CPP_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}  # New

# Derived set of all supported extensions
SUPPORTED_EXTENSIONS = (
    PYTHON_EXTENSIONS
    | JS_EXTENSIONS
    | GO_EXTENSIONS
    | TERRAFORM_EXTENSIONS
    | RUST_EXTENSIONS
    | JAVA_EXTENSIONS
    | C_CPP_EXTENSIONS  # New
)
```

**Step 2: Commit**

```bash
git add src/hackmenot/core/constants.py
git commit -m "feat(core): add C/C++ file extensions"
```

---

### Task 6: Wire CppParser into Scanner

**Files:**
- Modify: `src/hackmenot/core/scanner.py:22-27,36-42`
- Create: `tests/test_integration/test_cpp_scan.py`

**Step 1: Write integration test**

Create: `tests/test_integration/test_cpp_scan.py`

```python
"""Integration tests for C/C++ scanning."""

from pathlib import Path
import tempfile
import pytest

from hackmenot.core.scanner import Scanner


def test_scan_c_file():
    """Test scanning a C file."""
    scanner = Scanner()

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.c"
        test_file.write_text('''
        #include <string.h>

        void copy_data(char* dest, const char* src) {
            strcpy(dest, src);  // Unsafe
        }
        ''')

        result = scanner.scan([test_file])

        assert result.files_scanned == 1
        # Parser should work (findings checked in later tests)


def test_scan_cpp_file():
    """Test scanning a C++ file."""
    scanner = Scanner()

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.cpp"
        test_file.write_text('''
        #include <cstring>

        void process(char* buffer, const char* input) {
            strcpy(buffer, input);
        }
        ''')

        result = scanner.scan([test_file])

        assert result.files_scanned == 1
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_integration/test_cpp_scan.py -v`
Expected: FAIL with errors about C/C++ files not being scanned

**Step 3: Import CppParser in scanner**

Modify: `src/hackmenot/core/scanner.py`

```python
from hackmenot.parsers.cpp import CppParser  # Add this import
from hackmenot.parsers.golang import GoParser
from hackmenot.parsers.java import JavaParser
from hackmenot.parsers.javascript import JavaScriptParser
from hackmenot.parsers.python import PythonParser
from hackmenot.parsers.rust import RustParser
from hackmenot.parsers.terraform import TerraformParser
```

**Step 4: Add cpp_parser to Scanner __init__**

Modify: `src/hackmenot/core/scanner.py`

```python
def __init__(self, cache: FileCache | None = None, config: Config | None = None) -> None:
    self.parser = PythonParser()
    self.js_parser = JavaScriptParser()
    self.go_parser = GoParser()
    self.tf_parser = TerraformParser()
    self.rust_parser = RustParser()
    self.java_parser = JavaParser()
    self.cpp_parser = CppParser()  # Add this line
    self.engine = RulesEngine()
    self.cache = cache
    self.config = config or Config()
    self._load_rules()
```

**Step 5: Update _scan_file to route C/C++ files**

Find the `_scan_file` method and add C/C++ handling (around line 200):

```python
def _scan_file(self, file_path: Path) -> list[Finding]:
    """Scan a single file."""
    suffix = file_path.suffix.lower()

    if suffix in {".py"}:
        parse_result = self.parser.parse_file(file_path)
    elif suffix in JS_EXTENSIONS:
        parse_result = self.js_parser.parse_file(file_path)
    elif suffix in GO_EXTENSIONS:
        parse_result = self.go_parser.parse_file(file_path)
    elif suffix in RUST_EXTENSIONS:
        parse_result = self.rust_parser.parse_file(file_path)
    elif suffix in JAVA_EXTENSIONS:
        parse_result = self.java_parser.parse_file(file_path)
    elif suffix in C_CPP_EXTENSIONS:  # Add this block
        parse_result = self.cpp_parser.parse_file(file_path)
    elif suffix in TERRAFORM_EXTENSIONS:
        parse_result = self.tf_parser.parse_file(file_path)
    else:
        return []

    if parse_result.has_error:
        raise ValueError(parse_result.error_message or "Parse error")

    return self.engine.check_file(parse_result)
```

**Step 6: Import C_CPP_EXTENSIONS**

Add to imports in: `src/hackmenot/core/scanner.py`

```python
from hackmenot.core.constants import (
    DEFAULT_WORKERS,
    GO_EXTENSIONS,
    JAVA_EXTENSIONS,
    JS_EXTENSIONS,
    RUST_EXTENSIONS,
    SKIP_DIRS,
    SUPPORTED_EXTENSIONS,
    TERRAFORM_EXTENSIONS,
    C_CPP_EXTENSIONS,  # Add this
)
```

**Step 7: Run tests to verify they pass**

Run: `pytest tests/test_integration/test_cpp_scan.py -v`
Expected: PASS

**Step 8: Commit**

```bash
git add src/hackmenot/core/scanner.py tests/test_integration/test_cpp_scan.py
git commit -m "feat(scanner): wire CppParser into scanner"
```

---

### Task 7: Export CppParser in parsers module

**Files:**
- Modify: `src/hackmenot/parsers/__init__.py`

**Step 1: Add exports**

```python
from hackmenot.parsers.cpp import CppParser, CppParseResult  # Add this
from hackmenot.parsers.java import JavaParser, JavaParseResult
# ... rest of imports

__all__ = [
    # ... existing exports
    "CppParser",
    "CppParseResult",
]
```

**Step 2: Commit**

```bash
git add src/hackmenot/parsers/__init__.py
git commit -m "feat(parsers): export CppParser and CppParseResult"
```

---

## Phase 3: Memory Safety Rules (Days 4-5)

### Task 8: Create C/C++ Rules Directory

**Files:**
- Create: `src/hackmenot/rules/builtin/c-cpp/`

**Step 1: Create directory**

Run: `mkdir -p src/hackmenot/rules/builtin/c-cpp`

**Step 2: Verify**

Run: `ls -la src/hackmenot/rules/builtin/ | grep c-cpp`
Expected: Directory listed

---

### Task 9: Implement C_MEM001 - Buffer Overflow strcpy

**Files:**
- Create: `src/hackmenot/rules/builtin/c-cpp/C_MEM001.yml`
- Create: `tests/fixtures/c-cpp/vulnerable_strcpy.c`
- Modify: `tests/test_rules/test_c_cpp_rules.py`

**Step 1: Create test fixture**

Create: `tests/fixtures/c-cpp/vulnerable_strcpy.c`

```c
#include <string.h>

void unsafe_copy(char* dest, const char* src) {
    strcpy(dest, src);  // Vulnerable - no bounds check
}

void safe_copy(char* dest, const char* src, size_t dest_size) {
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';  // Safe - bounded
}
```

**Step 2: Write failing test**

Create: `tests/test_rules/test_c_cpp_rules.py`

```python
"""Tests for C/C++ security rules."""

from pathlib import Path
import pytest

from hackmenot.core.scanner import Scanner
from hackmenot.core.models import Severity


def test_C_MEM001_strcpy_detected(tmp_path):
    """Test C_MEM001 detects unsafe strcpy."""
    scanner = Scanner()

    test_file = tmp_path / "test.c"
    test_file.write_text('''
    #include <string.h>

    void copy_data(char* dest, const char* src) {
        strcpy(dest, src);
    }
    ''')

    result = scanner.scan([test_file])

    findings = [f for f in result.findings if f.rule_id == "C_MEM001"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "strcpy" in findings[0].message.lower()


def test_C_MEM001_safe_strncpy_not_flagged(tmp_path):
    """Test C_MEM001 doesn't flag safe strncpy."""
    scanner = Scanner()

    test_file = tmp_path / "test.c"
    test_file.write_text('''
    #include <string.h>

    void safe_copy(char* dest, const char* src, size_t size) {
        strncpy(dest, src, size - 1);
        dest[size - 1] = '\\0';
    }
    ''')

    result = scanner.scan([test_file])

    findings = [f for f in result.findings if f.rule_id == "C_MEM001"]
    assert len(findings) == 0
```

**Step 3: Run test to verify it fails**

Run: `pytest tests/test_rules/test_c_cpp_rules.py::test_C_MEM001_strcpy_detected -v`
Expected: FAIL (rule not found)

**Step 4: Create rule YAML**

Create: `src/hackmenot/rules/builtin/c-cpp/C_MEM001.yml`

```yaml
id: C_MEM001
name: Buffer Overflow - strcpy
severity: critical
category: memory-safety
languages:
  - c
  - cpp
pattern:
  type: call
  name: strcpy
message: |
  Using strcpy() without bounds checking can cause buffer overflow.

  The source string may be longer than the destination buffer,
  writing past buffer boundaries and corrupting memory.
fix: |
  Replace with strncpy() or strcpy_s():

  // Safe alternative:
  strncpy(dest, src, sizeof(dest) - 1);
  dest[sizeof(dest) - 1] = '\0';  // Ensure null termination

  // Or use strcpy_s (C11/MSVC):
  strcpy_s(dest, sizeof(dest), src);
education: |
  **Why AI makes this mistake:**
  AI assistants use strcpy() because:
  - It's simpler than safe alternatives
  - Training data contains legacy code examples
  - They don't consider buffer size constraints

  **Impact:**
  - Memory corruption
  - Arbitrary code execution
  - System compromise

  **Best practice:**
  Always use bounded string functions and verify buffer sizes.
```

**Step 5: Run tests to verify they pass**

Run: `pytest tests/test_rules/test_c_cpp_rules.py::test_C_MEM001_strcpy_detected -v`
Expected: PASS

**Step 6: Commit**

```bash
git add src/hackmenot/rules/builtin/c-cpp/C_MEM001.yml tests/fixtures/c-cpp/vulnerable_strcpy.c tests/test_rules/test_c_cpp_rules.py
git commit -m "feat(rules): add C_MEM001 strcpy buffer overflow rule"
```

---

### Task 10: Implement Remaining Memory Safety Rules

**Files:**
- Create: `src/hackmenot/rules/builtin/c-cpp/C_MEM002.yml` through `C_MEM008.yml`
- Modify: `tests/test_rules/test_c_cpp_rules.py`

**Note:** Follow the same TDD pattern for each rule:
1. Write test
2. Run failing
3. Create YAML rule
4. Run passing
5. Commit

**Rules to implement:**

**C_MEM002 - strcat**
```yaml
id: C_MEM002
name: Buffer Overflow - strcat
severity: critical
category: memory-safety
languages:
  - c
  - cpp
pattern:
  type: call
  name: strcat
message: Using strcat() without size validation can cause buffer overflow.
fix: Use strncat() with explicit size limit.
education: strcat() doesn't check destination buffer size.
```

**C_MEM003 - Use After Free**
```yaml
id: C_MEM003
name: Use After Free
severity: critical
category: memory-safety
languages:
  - c
  - cpp
pattern:
  type: call
  name: free
message: Potential use-after-free detected.
fix: Set pointer to NULL after free().
education: AI often forgets to nullify pointers after free().
```

**C_MEM004 - Double Free**
```yaml
id: C_MEM004
name: Double Free
severity: critical
category: memory-safety
languages:
  - c
  - cpp
pattern:
  type: call
  name: free
message: Potential double-free detected.
fix: Check if pointer is NULL before free().
education: Double-free causes heap corruption.
```

**C_MEM005 - NULL Dereference**
```yaml
id: C_MEM005
name: NULL Pointer Dereference
severity: high
category: memory-safety
languages:
  - c
  - cpp
pattern:
  type: pointer
  operation: dereference
message: Pointer dereferenced without NULL check.
fix: Add NULL check before dereferencing.
education: AI often skips NULL validation.
```

**C_MEM006 - Memory Leak**
```yaml
id: C_MEM006
name: Memory Leak - malloc without free
severity: medium
category: memory-safety
languages:
  - c
  - cpp
pattern:
  type: call
  name: malloc
message: malloc() call without corresponding free().
fix: Ensure all allocated memory is freed.
education: AI forgets resource cleanup.
```

**C_MEM007 - Stack Buffer Overflow**
```yaml
id: C_MEM007
name: Stack Buffer Overflow
severity: high
category: memory-safety
languages:
  - c
  - cpp
pattern:
  type: array
  unchecked_index: true
message: Array access without bounds check.
fix: Validate array index before access.
education: AI doesn't add bounds checking.
```

**C_MEM008 - Dangling Pointer**
```yaml
id: C_MEM008
name: Dangling Pointer - Return Stack Address
severity: critical
category: memory-safety
languages:
  - c
  - cpp
pattern:
  type: pointer
  operation: return_stack_address
message: Returning address of stack variable.
fix: Allocate on heap or use static variable.
education: Stack variables deallocated when function returns.
```

**Commit each rule individually:**

```bash
git add src/hackmenot/rules/builtin/c-cpp/C_MEM00X.yml tests/test_rules/test_c_cpp_rules.py
git commit -m "feat(rules): add C_MEM00X [rule name]"
```

---

## Phase 4: Unsafe Functions Rules (Day 6)

### Task 11: Implement Unsafe Function Rules

**Files:**
- Create: `src/hackmenot/rules/builtin/c-cpp/C_FN001.yml` through `C_FN006.yml`
- Modify: `tests/test_rules/test_c_cpp_rules.py`

**C_FN001 - gets()**
```yaml
id: C_FN001
name: Unsafe Function - gets
severity: critical
category: unsafe-functions
languages:
  - c
  - cpp
pattern:
  type: call
  name: gets
message: gets() is inherently unsafe - no bounds checking.
fix: Use fgets() instead.
education: gets() was removed from C11 standard.
```

**C_FN002 - sprintf()**
```yaml
id: C_FN002
name: Unsafe Function - sprintf
severity: high
category: unsafe-functions
languages:
  - c
  - cpp
pattern:
  type: call
  name: sprintf
message: sprintf() doesn't check buffer size.
fix: Use snprintf() with size limit.
education: AI uses sprintf for simplicity.
```

**C_FN003 - scanf("%s")**
```yaml
id: C_FN003
name: Unsafe Function - scanf without width
severity: high
category: unsafe-functions
languages:
  - c
  - cpp
pattern:
  type: call
  name: scanf
  format_string_contains: "%s"
message: scanf("%s") doesn't limit input size.
fix: Use scanf("%99s", buffer) with width specifier.
education: AI forgets width limits in format strings.
```

Follow same TDD pattern for C_FN004, C_FN005, C_FN006.

**Commit each rule:**

```bash
git add src/hackmenot/rules/builtin/c-cpp/C_FN00X.yml tests/test_rules/test_c_cpp_rules.py
git commit -m "feat(rules): add C_FN00X [rule name]"
```

---

## Phase 5: Injection & Integer Rules (Day 7)

### Task 12: Implement Injection Rules

**Files:**
- Create: `src/hackmenot/rules/builtin/c-cpp/C_INJ001.yml` through `C_INJ004.yml`

**C_INJ001 - Command Injection**
```yaml
id: C_INJ001
name: Command Injection - system()
severity: critical
category: injection
languages:
  - c
  - cpp
pattern:
  type: call
  name: system
message: User input in system() can lead to command injection.
fix: Validate and sanitize input, or use safer APIs.
education: AI concatenates user input into shell commands.
```

**C_INJ002 - SQL Injection**
```yaml
id: C_INJ002
name: SQL Injection - String Concatenation
severity: critical
category: injection
languages:
  - c
  - cpp
pattern:
  type: string
  contains: "SELECT"
message: String concatenation for SQL queries enables injection.
fix: Use parameterized queries.
education: AI builds SQL with string concatenation.
```

**C_INJ003 - Format String**
```yaml
id: C_INJ003
name: Format String Vulnerability
severity: critical
category: injection
languages:
  - c
  - cpp
pattern:
  type: call
  name: printf
  user_controlled_format: true
message: User-controlled format string in printf().
fix: Use printf("%s", user_input) never printf(user_input).
education: AI passes user input directly to printf.
```

**C_INJ004 - Path Traversal**
```yaml
id: C_INJ004
name: Path Traversal - fopen
severity: high
category: injection
languages:
  - c
  - cpp
pattern:
  type: call
  name: fopen
message: Unsanitized file path in fopen().
fix: Validate path doesn't contain ../ sequences.
education: AI doesn't sanitize file paths.
```

Follow TDD for each rule.

---

### Task 13: Implement Integer Issue Rules

**Files:**
- Create: `src/hackmenot/rules/builtin/c-cpp/C_INT001.yml` through `C_INT005.yml`

**C_INT001 - Integer Overflow**
```yaml
id: C_INT001
name: Integer Overflow
severity: high
category: integer-issues
languages:
  - c
  - cpp
pattern:
  type: binary_expression
  operation: "+"
message: Integer addition without overflow check.
fix: Check for overflow before arithmetic.
education: AI doesn't add overflow checks.
```

Follow TDD for C_INT002 through C_INT005.

**Final commit:**

```bash
git add src/hackmenot/rules/builtin/c-cpp/C_INT*.yml tests/test_rules/test_c_cpp_rules.py
git commit -m "feat(rules): add integer issue rules"
```

---

## Phase 6: Documentation (Day 8)

### Task 14: Update README

**Files:**
- Modify: `README.md`

**Step 1: Add C/C++ to language badge**

Update line 16:
```markdown
![6 Languages](https://img.shields.io/badge/languages-Python%20%7C%20JS%20%7C%20Go%20%7C%20Rust%20%7C%20Java%20%7C%20C%2FC%2B%2B%20%7C%20Terraform-orange)
```

**Step 2: Add to "What It Catches" table**

Add C/C++ examples to the table.

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add C/C++ to README"
```

---

### Task 15: Run Full Test Suite

**Step 1: Run all tests**

Run: `pytest tests/ -v`
Expected: 630+ tests PASS

**Step 2: Check coverage**

Run: `pytest tests/ --cov=src/hackmenot --cov-report=term-missing`
Expected: >85% coverage

---

### Task 16: Final Integration Test

**Step 1: Create test C++ project**

```bash
mkdir -p /tmp/test-cpp-project
cat > /tmp/test-cpp-project/main.cpp << 'EOF'
#include <cstring>
#include <cstdio>

void unsafe_function(char* buffer, const char* input) {
    strcpy(buffer, input);  // Should trigger C_MEM001
    sprintf(buffer, "%s", input);  // Should trigger C_FN002
}

int main() {
    char buf[100];
    gets(buf);  // Should trigger C_FN001
    return 0;
}
EOF
```

**Step 2: Run hackmenot**

Run: `hackmenot scan /tmp/test-cpp-project/`
Expected: 3 findings (C_MEM001, C_FN001, C_FN002)

**Step 3: Verify output**

Check that all rules trigger correctly and messages are clear.

---

### Task 17: Create Release Commit

**Step 1: Update version if needed**

Check `pyproject.toml` version.

**Step 2: Final commit**

```bash
git add .
git commit -m "feat: add C/C++ language support with 20-30 security rules

- Add CppParser using tree-sitter-cpp for both C and C++
- Implement 8-10 memory safety rules (buffer overflow, use-after-free, etc.)
- Implement 6-8 unsafe function rules (gets, strcpy, sprintf, etc.)
- Implement 4-6 injection rules (command, SQL, format string, path traversal)
- Implement 4-6 integer issue rules (overflow, underflow, signedness)
- Full test coverage (630+ tests)
- Update documentation

Closes #XXX"
```

---

## Testing Checklist

After implementation, verify:

- [ ] All 630+ tests passing
- [ ] Coverage >85%
- [ ] `hackmenot scan` detects C/C++ files
- [ ] C_MEM001-C_MEM008 rules working
- [ ] C_FN001-C_FN006 rules working
- [ ] C_INJ001-C_INJ004 rules working
- [ ] C_INT001-C_INT005 rules working
- [ ] Parallel scanning works with C/C++ files
- [ ] SARIF output includes C/C++ findings
- [ ] Performance <2s for 1000 C/C++ files

---

## Success Metrics

- **Parser Accuracy**: >95%
- **Rule Coverage**: 20-30 rules
- **Test Coverage**: >85%
- **Performance**: <2s for 1000 files
- **False Positive Rate**: <5%
