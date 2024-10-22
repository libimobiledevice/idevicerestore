#!/bin/bash
set -e
cd "$(dirname "$0")"

docker build . -t idevicerestore-docker
docker run -it --privileged --net=host -v /run/udev/control:/run/udev/control -v "$(pwd):/tmp" idevicerestore-docker idevicerestore --latest
