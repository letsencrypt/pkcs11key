#!/bin/bash -exv
#
# This doesn't really need to be run again. I ran it once to set up a SoftHSM
# directory, but then checked in the SoftHSM files so run.sh can be run
# repeatedly with the same slot ids.

cd $(dirname $0)/v4
export MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
export SOFTHSM2_CONF=${PWD}/softhsm.conf
echo "directories.tokendir = ${PWD}/softhsm/" > ${SOFTHSM2_CONF}

softhsm2-util --module "${MODULE}" --free --init-token --label silly_signer --pin 1234 --so-pin 1234 > slot-assignment.txt
SLOT_ASSIGNMENT=$(sed -n 's/.*to slot \(.\+\)/\1/p' slot-assignment.txt)
softhsm2-util --module "${MODULE}" --slot "${SLOT_ASSIGNMENT}" --import ../v4/testdata/silly_signer.key --label silly_signer_key --pin 1234 --id F00D
softhsm2-util --module "${MODULE}" --free --init-token --label entropic_ecdsa --pin 1234 --so-pin 1234 > slot-assignment.txt
SLOT_ASSIGNMENT=$(sed -n 's/.*to slot \(.\+\)/\1/p' slot-assignment.txt)
softhsm2-util --module "${MODULE}" --slot "${SLOT_ASSIGNMENT}" --import ../v4/testdata/entropic_ecdsa.key --label entropic_ecdsa_key --pin 1234 --id C0FFEE

softhsm2-util --module "${MODULE}" --show-slots
