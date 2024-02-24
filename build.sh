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
  "${OUT_DIR}/${cmd}" version
}

version() {
  local version_tag
  version_tag=$(git_version_tag)
  local version_file="${SELF_DIR}/cmd/version.go"
  sed -e "s|#VERSION|${version_tag}|g" < "${version_file}-e" > "${version_file}"
}

git_version_tag() {
  local exact_tag
  exact_tag=$(git describe --tags --exact-match 2>/dev/null || echo '')
  if [ -n "$exact_tag" ]; then
    echo "$exact_tag"
  else
    local latest_tag
    latest_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo 'v0')
    local latest_commit
    latest_commit=$(git rev-parse --short=7 HEAD)
    echo "$latest_tag-$latest_commit"
  fi
}

version
check
cleanup
build .
