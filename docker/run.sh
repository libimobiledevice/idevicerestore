#!/bin/bash
set -e
cd "$(dirname "$0")"

docker build . -t idevicerestore-docker
docker rm --force idevicerestore || true

docker run --name idevicerestore -it --privileged --net=host -v /dev:/dev -v /run/udev/control:/run/udev/control -v "$(pwd):/tmp" idevicerestore-docker idevicerestore.sh "$@"

