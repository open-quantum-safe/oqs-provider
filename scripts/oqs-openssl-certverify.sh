#!/bin/bash

# Use dockerimage to verify certs for alg $1

IMAGE=openquantumsafe/curl

if [ $# -ne 1 ]; then
    echo "Usage: $0 <algorithmname>. Exiting."
    exit 1
fi

if [ ! -d tmp ]; then
    echo "Test folder tmp not existing. Exiting."
    exit 1
fi

if [ ! -f tmp/$1_srv.crt ]; then
    echo "Cert to test not present. Exiting."
    exit 1
fi

docker run -v `pwd`/tmp:/home/oqs/data -it $IMAGE sh -c "cd /home/oqs/data && openssl verify -CAfile $1_CA.crt $1_srv.crt"
