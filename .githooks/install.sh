#!/bin/sh
#
# install.sh — run once after cloning
#

set -eu
repo_root=$(git rev-parse --show-toplevel)

cd "$repo_root"
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit .githooks/pre-push

echo "Hooks enabled (core.hooksPath=.githooks)."
