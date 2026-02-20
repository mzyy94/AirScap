#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi

if [ "$1" = "configure" ] && [ -z "$2" ]; then
    echo ""
    echo "airscap installed successfully."
    echo ""
    echo "To get started:"
    echo "  1. Edit /etc/airscap/env and set your scanner password"
    echo "  2. sudo systemctl enable --now airscap"
    echo ""
fi
