#!/bin/bash

cd oqs-template

rm generate.yml

# Step 1: Obtain current generate.yml from main:
wget -c https://raw.githubusercontent.com/open-quantum-safe/openssl/OQS-OpenSSL_1_1_1-stable/oqs-template/generate.yml

# Step 2: Run the generator:
cd .. && python3 oqs-template/generate.py

# Step 3: Run clang-format.
find . -type f -and '(' -name '*.h' -or -name '*.c' -or -name '*.inc' ')' | xargs "${CLANG_FORMAT:-clang-format}" -i
