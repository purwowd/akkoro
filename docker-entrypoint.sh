#!/bin/sh
set -e
# /dev is a devtmpfs in containers, so the tun node must be created at runtime.
if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 || true
fi
exec akkoro "$@"
