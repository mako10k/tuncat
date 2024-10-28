#!/bin/bash

set -xe

if ! getent group docker &> /dev/null; then
    sudo groupadd docker
    sudo usermod -aG docker "$USER"
    sudo chown root:docker /var/run/docker.sock
    sudo chmod 660 /var/run/docker.sock
fi

exec "$0" "$@"