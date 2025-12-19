#!/bin/bash
set -e

# Step 1: Run the generator:
python3 oqs-template/generate.py

# Step 2: Run clang-format.
echo "Run do-code-format.sh"
./scripts/do_code_format.sh --no-dry-run