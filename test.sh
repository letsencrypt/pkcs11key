#!/bin/bash -ex
#
# Instantiate a SoftHSM token, then run tests, including the benchmark. Provide
# flags allowing the benchmark to use the SoftHSM token.
#

if [ -r /proc/brcm_monitor0 ]; then
  echo "The /proc/brcm_monitor0 file has open permissions. Please run"
  echo " # chmod 600 /proc/brcm_monitor0"
  echo "as root to avoid crashing the system."
  echo https://bugs.launchpad.net/ubuntu/+source/bcmwl/+bug/1450825
  exit 2
fi

DIR=$(mktemp -d -t softhXXXX)
export SOFTHSM_CONF=${DIR}/softhsm.conf
SLOT=0
echo ${SLOT}:${DIR}/softhsm-slot0.db > ${SOFTHSM_CONF}
softhsm --slot ${SLOT} --init-token --label silly_signer --pin 1234 --so-pin 5678
softhsm --slot ${SLOT} --import testdata/silly_signer.key --label silly_signer_key --pin 1234 --id F00D

go test github.com/letsencrypt/pkcs11key -module /usr/lib/softhsm/libsofthsm.so \
  -pin 1234 -tokenLabel "silly_signer" \
  -privateKeyLabel silly_signer_key \
  -test.bench Bench \
  -sessions 10
rm -r ${DIR}
