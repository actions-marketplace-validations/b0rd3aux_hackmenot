# C/C++ Language Support - Design Document

**Date:** 2026-02-14
**Status:** Approved
**Target:** Add comprehensive C/C++ security scanning to hackmenot

---

## 1. Overview

Add C and C++ language support to hackmenot with 20-30 security rules covering memory safety, injection flaws, integer issues, and unsafe function usage.

### Goals

1. **Unified C/C++ Support** - Handle both C and C++ with a single parser
2. **Comprehensive Coverage** - 20-30 rules across 4 priority vulnerability categories
3. **Memory Safety Focus** - Detect buffer overflows, use-after-free, memory leaks
4. **AI-Aware Rules** - Target patterns AI assistants commonly introduce
5. **Zero Breaking Changes** - Integrate seamlessly with existing architecture

---

## 2. Architecture

### Component Structure

- **CppParser** - Uses tree-sitter-cpp for both C and C++
- **Extensions**: `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp`, `.hxx`
- **Detects**: Function calls, unsafe functions, pointers, arrays, strings, integers

### Integration Points

1. **constants.py** - Add C_CPP_EXTENSIONS
2. **scanner.py** - Add cpp_parser instance
3. **parsers/__init__.py** - Export CppParser and CppParseResult
4. **rules/builtin/c-cpp/** - Rule definitions

---

## 3. Parser Implementation

### CppParser Class

Main parser class using tree-sitter-cpp to extract security-relevant patterns from C/C++ code.

### Info Dataclasses

- **CppCallInfo** - Function calls
- **CppUnsafeFunctionInfo** - Unsafe function usage with context
- **CppPointerInfo** - Pointer operations
- **CppArrayInfo** - Array access patterns
- **CppStringInfo** - String literals and format strings

---

## 4. Rule Categories (20-30 rules)

### Memory Safety (8-10 rules)
- C_MEM001: Buffer Overflow - strcpy
- C_MEM002: Buffer Overflow - strcat
- C_MEM003: Use After Free
- C_MEM004: Double Free
- C_MEM005: NULL Dereference
- C_MEM006: Memory Leak
- C_MEM007: Stack Buffer Overflow
- C_MEM008: Dangling Pointer

### Unsafe Functions (6-8 rules)
- C_FN001: Unsafe gets()
- C_FN002: Unsafe sprintf()
- C_FN003: Unsafe scanf()
- C_FN004: Unsafe vsprintf()
- C_FN005: Unsafe strncpy()
- C_FN006: Unsafe strtok()

### Injection Flaws (4-6 rules)
- C_INJ001: Command Injection
- C_INJ002: SQL Injection
- C_INJ003: Format String Vulnerability
- C_INJ004: Path Traversal

### Integer Issues (4-6 rules)
- C_INT001: Integer Overflow
- C_INT002: Integer Underflow
- C_INT003: Signedness Errors
- C_INT004: Type Truncation
- C_INT005: Off-by-One Errors

---

## 5. Implementation Phases

**Phase 1 (Days 1-2):** Parser foundation - CppParser class and tests

**Phase 2 (Day 3):** Scanner integration

**Phase 3 (Days 4-5):** Memory safety rules

**Phase 4 (Day 6):** Unsafe function rules

**Phase 5 (Day 7):** Injection and integer rules

**Phase 6 (Day 8):** Documentation and polish

**Total: ~8 days (1-1.5 weeks)**

---

## 6. Success Criteria

- Parser accuracy >95%
- 20-30 rules implemented with tests
- Test coverage >85%
- Performance <2s for 1000 files
- Zero breaking changes to existing features

---

## 7. Decision Log

### Why unified parser?
- C++ grammar includes C syntax
- Simpler architecture
- Matches existing JS/TS pattern
- Less code duplication

### Why 20-30 rules?
- Comprehensive coverage
- Matches/exceeds existing languages
- Balances scope vs timeline

### Why tree-sitter over libclang?
- Consistent with existing parsers
- Lightweight (no LLVM)
- Faster for pattern detection
