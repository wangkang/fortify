#!/usr/bin/env bash

set -euo pipefail

declare SELF
SELF=$(readlink -f "$0")
declare -r SELF_DIR=${SELF%/*}
declare -r OUT_DIR=${SELF_DIR:?}/build

check() {
  if ! command -v go &>/dev/null; then
    echo "Error: Go language environment not found." >&2
    exit 1
  fi
  printf "Check: " >&1
  which go >&1
}

cleanup() {
  mkdir -p "${OUT_DIR}"
  if [ -d "${OUT_DIR}" ]; then
    rm -rf "${OUT_DIR:?}"/*
  fi
  mkdir -p "${OUT_DIR}/sss"
  mkdir -p "${OUT_DIR}/rsa"
}

build() {
  pushd "${SELF_DIR}/${1:-.}" >/dev/null || exit 1
  echo "Build: ${PWD}" >&1
  go mod tidy || {
    echo "Error: Failed to tidy Go modules." >&2
    exit 1
  }
  if ! go mod download; then
    echo "Error: Failed to download dependencies. Retrying..." >&2
    go clean -modcache
    go mod download || {
      echo "Error: Still failed to download dependencies. Exiting." >&2
      exit 1
    }
  fi
  gofmt -w -l -d -s .
  local cmd="${PWD##*/}"
  local file
  file="${cmd}-$(go env GOHOSTOS)-$(go env GOARCH)"
  file=$(echo "${file}" | tr '[:upper:]' '[:lower:]')
  go build -ldflags "-s -w" -o "${OUT_DIR}/${file}"
  echo -e "Built: ${OUT_DIR}/${file}" >&1
  ln -s "${OUT_DIR}/${file}" "${OUT_DIR}/${cmd}"
  popd >/dev/null || exit 1
}

check
cleanup
build .
