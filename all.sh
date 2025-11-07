#!/bin/sh

set -euo pipefail

cd python || exit 1
./tests.sh
#TODO: add example