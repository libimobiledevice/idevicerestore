#!/bin/bash
set -e

usbmuxd &

idevicerestore "$@"

