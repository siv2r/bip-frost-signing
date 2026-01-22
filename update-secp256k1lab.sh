#!/bin/sh

# Update the secp256k1lab git subtree to the latest upstream version
#
# The secp256k1lab library is vendored as a git subtree at python/secp256k1lab/
# This script updates it to the latest version from the upstream repository.

git fetch https://github.com/secp256k1lab/secp256k1lab.git master
git subtree pull --prefix=python/secp256k1lab https://github.com/secp256k1lab/secp256k1lab.git master --squash