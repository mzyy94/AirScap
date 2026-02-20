#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl stop airscap 2>/dev/null || true
    if [ "$1" = "remove" ]; then
        systemctl disable airscap 2>/dev/null || true
    fi
fi
