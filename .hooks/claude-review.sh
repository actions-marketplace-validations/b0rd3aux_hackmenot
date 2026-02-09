#!/bin/bash
# Claude Code review hook for pre-commit
# Skips if claude CLI is not installed

# Check if claude is available
if ! command -v claude &> /dev/null; then
    echo "Claude CLI not found, skipping AI review"
    exit 0
fi

# Get staged diff
DIFF=$(git diff --cached --diff-filter=ACMR)

if [ -z "$DIFF" ]; then
    echo "No staged changes to review"
    exit 0
fi

# Run Claude review
echo "Running Claude Code review on staged changes..."
echo "$DIFF" | claude --print "Review this diff for:
1. Broad exception catching (should use specific exceptions)
2. Missing error handling
3. Security issues
4. Magic numbers that should be constants
5. os.walk usage (should use pathlib.rglob)

Be concise. Only report actual issues, not suggestions. Format as a bullet list."

# Always exit 0 - this is advisory, not blocking
exit 0
