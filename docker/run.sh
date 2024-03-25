#!/bin/bash
cd "$(dirname "$0")"

docker build . -t idevicerestore-docker
docker run -it --privileged -v "$(pwd):/tmp" idevicerestore-docker idevicerestore --latest