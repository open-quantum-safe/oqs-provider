#/bin/bash

OQS_ENCODING_DILITHIUM2=draft-uni-qsckeys-dilithium-00/sk-pk \
OQS_ENCODING_DILITHIUM3=draft-uni-qsckeys-dilithium-00/sk-pk \
OQS_ENCODING_DILITHIUM5=draft-uni-qsckeys-dilithium-00/sk-pk \
OQS_ENCODING_DILITHIUM2_AES=draft-uni-qsckeys-dilithium-00/sk-pk \
OQS_ENCODING_DILITHIUM3_AES=draft-uni-qsckeys-dilithium-00/sk-pk \
OQS_ENCODING_DILITHIUM5_AES=draft-uni-qsckeys-dilithium-00/sk-pk \
OQS_ENCODING_FALCON512=draft-uni-qsckeys-falcon-00/sk-pk \
OQS_ENCODING_FALCON1024=draft-uni-qsckeys-falcon-00/sk-pk \
OQS_ENCODING_SPHINCSHARAKA128FROBUST=draft-uni-qsckeys-sphincsplus-00/sk-pk \
OQS_ENCODING_SPHINCSHARAKA128FSIMPLE=draft-uni-qsckeys-sphincsplus-00/sk-pk \
OQS_ENCODING_SPHINCSSHA256128FROBUST=draft-uni-qsckeys-sphincsplus-00/sk-pk \
OQS_ENCODING_SPHINCSSHA256128SSIMPLE=draft-uni-qsckeys-sphincsplus-00/sk-pk \
OQS_ENCODING_SPHINCSSHAKE256128FSIMPLE=draft-uni-qsckeys-sphincsplus-00/sk-pk \
scripts/runtests.sh $@