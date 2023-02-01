#!/bin/bash
set -e
cd "$(dirname "$0")"

docker build . -t idevicerestore-docker --no-cache

echo "You can now use 'run.sh --latest' to run the restore."

