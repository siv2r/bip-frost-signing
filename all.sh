#!/bin/sh

set -euo pipefail

cd reference || exit 1
./tests.sh
#TODO: add example