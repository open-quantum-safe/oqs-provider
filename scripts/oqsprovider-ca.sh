#!/bin/bash

# Test openssl CA functionality using oqsprovider for alg $1

if [ $# -ne 1 ]; then
    echo "Usage: $0 <algorithmname>. Exiting."
    exit 1
fi

if [ -z "$OPENSSL_APP" ]; then
    echo "OPENSSL_APP env var not set. Exiting."
    exit 1
fi

if [ -z "$OPENSSL_MODULES" ]; then
    echo "Warning: OPENSSL_MODULES env var not set."
fi

if [ -z "$OPENSSL_CONF" ]; then
    echo "Warning: OPENSSL_CONF env var not set."
fi

# Set OSX DYLD_LIBRARY_PATH if not already externally set
if [ -z "$DYLD_LIBRARY_PATH" ]; then
    export DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH
fi

echo "oqsprovider-ca.sh commencing..."

#rm -rf tmp
mkdir -p tmp && cd tmp
rm -rf demoCA && mkdir -p demoCA/newcerts
touch demoCA/index.txt
echo '01' > demoCA/serial
$OPENSSL_APP req -x509 -new -newkey $1 -keyout $1_rootCA.key -out $1_rootCA.crt -subj "/CN=test CA" -nodes

if [ $? -ne 0 ]; then
   echo "Failed to generate root CA. Exiting."
   exit 1
fi

$OPENSSL_APP req -new -newkey $1 -keyout $1.key -out $1.csr -nodes -subj "/CN=test Server"

if [ $? -ne 0 ]; then
   echo "Failed to generate test server CSR. Exiting."
   exit 1
fi

# Compute start and end dates (UTC) for certificate validity
# Default validity is 365 days; override with OQS_CA_DAYS environment variable

compute_utc_date() {
    # $1 = optional offset in days (integer)
    local offset="$1"
    local fmt="%Y%m%d%H%M%SZ"
    local res=""

    # Prefer GNU coreutils date (gdate) if installed (common on macOS via coreutils)
    if command -v gdate >/dev/null 2>&1; then
        if [ -z "$offset" ]; then
            res=$(gdate -u +"$fmt" 2>/dev/null) || res=""
        else
            res=$(gdate -u -d "+${offset} days" +"$fmt" 2>/dev/null) || res=""
        fi
    fi

    # Try GNU date (Linux)
    if [ -z "$res" ]; then
        if [ -z "$offset" ]; then
            if res=$(date -u +"$fmt" 2>/dev/null); then :; fi
        else
            if res=$(date -u -d "+${offset} days" +"$fmt" 2>/dev/null); then :; fi
        fi
    fi

    # Try BSD/macOS date (-v)
    if [ -z "$res" ]; then
        if [ -z "$offset" ]; then
            if res=$(date -u +"$fmt" 2>/dev/null); then :; fi
        else
            if res=$(date -u -v +${offset}d +"$fmt" 2>/dev/null); then :; fi
        fi
    fi

    # Python3 fallback
    if [ -z "$res" ] && command -v python3 >/dev/null 2>&1; then
        if [ -z "$offset" ]; then
            res=$(python3 - <<PY
from datetime import datetime
print(datetime.utcnow().strftime("%Y%m%d%H%M%SZ"))
PY
)
        else
            local off="$offset"
            res=$(python3 - <<PY
from datetime import datetime, timedelta
print((datetime.utcnow() + timedelta(days=int("$off"))).strftime("%Y%m%d%H%M%SZ"))
PY
)
        fi
    fi

    printf "%s" "$res"
}

START_DATE=$(compute_utc_date)
DAYS=${OQS_CA_DAYS:-365}
END_DATE=$(compute_utc_date "$DAYS")

if [ -z "$START_DATE" ]; then
    echo "Warning: could not compute START_DATE using date or python; defaulting to 2025-08-01 00:00:00Z"
    START_DATE="20250801000000Z"
fi

if [ -z "$END_DATE" ]; then
    echo "Warning: could not compute END_DATE using date or python; defaulting to 2030-01-01 00:00:00Z"
    END_DATE="20300101000000Z"
fi

$OPENSSL_APP ca -batch -startdate "$START_DATE" -enddate "$END_DATE" -keyfile $1_rootCA.key -cert $1_rootCA.crt -policy policy_anything -notext -out $1.crt -infiles $1.csr

if [ $? -ne 0 ]; then
   echo "Failed to generate server CRT. Exiting."
   exit 1
fi

# Don't forget to use provider(s) when not activated via config file
$OPENSSL_APP verify -CAfile $1_rootCA.crt $1.crt

