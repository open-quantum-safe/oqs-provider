#!/bin/bash

cd oqs-template

# Step 2: Run the generator:
cd .. && python3 oqs-template/generate.py

# Step 3: Run clang-format.
find . -type f -and '(' -name '*.h' -or -name '*.c' -or -name '*.inc' ')' | xargs "${CLANG_FORMAT:-clang-format}" -i
