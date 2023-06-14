#!/bin/bash -ex
#
# Instantiate a SoftHSM token, then run tests, including the benchmark. Provide
# flags allowing the benchmark to use the SoftHSM token.
#
# You can use a different PKCS#11 module by setting the MODULE environment
# variable, though you will still need the softhsm or softhsm2-util command
# line tool to initialize the token(s) and load the key(s). For instance:
#
# export MODULE=/usr/local/lib/libpkcs11-proxy.so PKCS11_PROXY_SOCKET=tcp://hsm.example.com:5657
# bash test.sh
#
# To test with a YubiKey 4:
#
# ykman piv generate-key --algorithm ECCP256 9a pubkey.pem
# ykman piv generate-certificate --pin 123456 --subject "yubico" 9a pubkey.pem
# ykman piv export-certificate 9a cert.pem
# go test -bench=. -module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
#   -pin 123456 -cert cert.pem -tokenLabel yubico
#
# You can also override the number of sessions by setting the SESSIONS variable.

if [ -r /proc/brcm_monitor0 ]; then
  echo "The /proc/brcm_monitor0 file has open permissions. Please run"
  echo " # chmod 600 /proc/brcm_monitor0"
  echo "as root to avoid crashing the system."
  echo https://bugs.launchpad.net/ubuntu/+source/bcmwl/+bug/1450825
  exit 2
fi

cd $(dirname $0)/v4

trap cleanUp EXIT
function cleanUp {
    if [ -d "./softhsm/" ]; then
        rm -rf ./softhsm/*
        git reset -- softhsm
        git checkout -- softhsm
    fi
}

export MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
export SOFTHSM2_CONF=${PWD}/softhsm.conf
echo "directories.tokendir = ${PWD}/softhsm/" > ${SOFTHSM2_CONF}
softhsm2-util --module "${MODULE}" --show-slots

go test github.com/letsencrypt/pkcs11key/v4

# Run the benchmark. Arguments: $1: token label, $2: certificate filename
function bench {
  go test github.com/letsencrypt/pkcs11key/v4 \
    -module ${MODULE} \
    -test.run xxxNONExxx \
    -pin 1234 \
    -tokenLabel ${1} \
    -cert ${2} \
    -test.bench Bench \
    -benchtime 10s \
    -sessions ${SESSIONS:-2};
}

bench silly_signer testdata/silly_signer.pem

if [ -n "${SOFTHSM2_CONF}" ] ; then
  bench entropic_ecdsa testdata/entropic_ecdsa.pem
fi
