#!/bin/bash
set -e
cd "$(dirname "$0")"

if [[ -z $(docker images | grep idevicerestore-docker) ]]; then
    echo "Container not built, you will need to build it with 'build.sh'"
    exit -1
fi

docker rm --force idevicerestore || true

docker run --name idevicerestore -it --privileged --net=host -v /dev:/dev -v /run/udev/control:/run/udev/control -v "$(pwd):/tmp" idevicerestore-docker idevicerestore.sh "$@"

