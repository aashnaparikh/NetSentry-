#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"
mkdir -p build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)"

sudo ./netsentry "$@"
