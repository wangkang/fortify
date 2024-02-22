#!/usr/bin/env bash

set -euo pipefail

declare SELF
SELF=$(readlink -f "$0")
declare -r SELF_DIR=${SELF%/*}

echo -n "Enter passphrase: "
stty -echo
read -r passphrase
stty echo
#read -rp "Enter passphrase: " passphrase
echo

if [ -n "${passphrase}" ]; then
  declare -r dir=${SELF_DIR:?}/debug/key_rsa
else
  declare -r dir=${SELF_DIR:?}/debug/key_rsa_unsafe
fi

mkdir -p "${dir}"
pushd "${dir}"

ssh-keygen -t rsa -b 4096 -C "fortify@struqt.com" -N "${passphrase}" -f id_rsa

cat id_rsa >id_rsa_pkcs8
chmod 600 id_rsa_pkcs8
ssh-keygen -f id_rsa_pkcs8 -m PKCS8 -p -N "${passphrase}" -P "${passphrase}"
ssh-keygen -f id_rsa.pub   -m PKCS8 -e >id_rsa_pkcs8.pub

cat id_rsa >id_rsa_rfc4716
chmod 600 id_rsa_rfc4716
ssh-keygen -f id_rsa_rfc4716 -m RFC4716 -p -N "${passphrase}" -P "${passphrase}"
ssh-keygen -f id_rsa.pub     -m RFC4716 -e >id_rsa_rfc4716.pub

cat id_rsa >id_rsa_pem
chmod 600 id_rsa_pem
ssh-keygen -f id_rsa_pem -m PEM -p -N "${passphrase}" -P "${passphrase}"
ssh-keygen -f id_rsa.pub -m PEM -e >id_rsa_pem.pub

popd
