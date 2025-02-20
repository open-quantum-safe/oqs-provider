#!/bin/bash
set -e

# Step 1: Run the generator:
python3 oqs-template/generate.py

# Step 2: Run clang-format.
echo "Run ${CLANG_FORMAT:-clang-format}"
find . -type f -and '(' -name '*.h' -or -name '*.c' -or -name '*.inc' ')' | xargs "${CLANG_FORMAT:-clang-format}" --style="{BasedOnStyle: llvm, IndentWidth: 4}" -i --Werror
