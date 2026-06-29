#!/usr/bin/env bash
# bench_kem_encoders.sh — detect OQS_KEM_ENCODERS keygen throughput regression
#
# Usage:
#   ./scripts/bench_kem_encoders.sh [BUILD_DIR] [OPENSSL_DIR] [ALGORITHMS]
#
# Arguments:
#   BUILD_DIR    directory containing oqsprovider library
#                (default: _build_enc)
#   OPENSSL_DIR  OpenSSL installation prefix containing bin/openssl
#                (default: auto-detected from PATH)
#   ALGORITHMS   space-separated list of KEM algorithm names to benchmark
#                (default: p256_mlkem512 p384_mlkem768 p521_mlkem1024 x25519_mlkem512)
#
# Exit codes:
#   0  all algorithms meet the minimum keygen/s threshold
#   1  one or more algorithms fall below threshold (regression detected)
#   2  usage or environment error

set -euo pipefail

BUILD_DIR="${1:-_build_enc}"
OPENSSL_BIN="${2:-openssl}"
ALGORITHMS="${3:-p256_mlkem512 p384_mlkem768 p521_mlkem1024 x25519_mlkem512}"

# Minimum acceptable keygen/s for P-curve hybrid KEMs with OQS_KEM_ENCODERS=ON.
# Thresholds are set at ~50% of observed keygen/s on a reference
# Apple M-series machine with OpenSSL 3.6.2 and OQS_KEM_ENCODERS=ON,
# intentionally conservative to catch catastrophic regressions without
# being fragile to normal run-to-run variance. Adjust for your hardware.

threshold_for_alg() {
    case "$1" in
        p256_mlkem512) echo 300 ;;
        p384_mlkem768) echo 150 ;;
        p521_mlkem1024) echo 150 ;;
        x25519_mlkem512) echo 5000 ;;
        *) return 1 ;;
    esac
}

# Locate provider library
PROVIDER_PATH="${BUILD_DIR}/lib"
if [ ! -d "${PROVIDER_PATH}" ]; then
    echo "ERROR: provider directory not found: ${PROVIDER_PATH}" >&2
    echo "       Build with: cmake -S . -B ${BUILD_DIR} -DOQS_KEM_ENCODERS=ON && make -C ${BUILD_DIR}" >&2
    exit 2
fi

echo "=== OQS KEM encoder hotpath benchmark ==="
echo "Provider: ${PROVIDER_PATH}"
echo "OpenSSL:  $(${OPENSSL_BIN} version)"
echo ""

FAILED=0

for ALG in ${ALGORITHMS}; do
    THRESHOLD="$(threshold_for_alg "${ALG}")"

    # Run openssl speed and extract keygen/s (3rd to last column of the result line)
    RESULT=$(${OPENSSL_BIN} speed \
        -provider-path "${PROVIDER_PATH}" \
        -provider oqsprovider \
        -provider default \
        "${ALG}" 2>&1 | grep "^[[:space:]]*${ALG}" | awk '{print $(NF-2)}')

    if [ -z "${RESULT}" ]; then
        echo "SKIP  ${ALG}: no result from openssl speed (algorithm may not be available)"
        continue
    fi

    # Compare as integers (floor)
    RESULT_INT=$(echo "${RESULT}" | awk '{printf "%d", $1}')
    THRESHOLD_INT=$(echo "${THRESHOLD}" | awk '{printf "%d", $1}')

    if [ "${RESULT_INT}" -ge "${THRESHOLD_INT}" ]; then
        echo "PASS  ${ALG}: ${RESULT} keygen/s (threshold: ${THRESHOLD})"
    else
        echo "FAIL  ${ALG}: ${RESULT} keygen/s is below threshold ${THRESHOLD} — possible encoder hotpath regression"
        FAILED=1
    fi
done

echo ""
if [ "${FAILED}" -eq 0 ]; then
    echo "All algorithms pass. No encoder hotpath regression detected."
else
    echo "One or more algorithms failed. Check OQS_KEM_ENCODERS build and oqsprov_keys.c for encoder scan regressions."
fi

exit "${FAILED}"
