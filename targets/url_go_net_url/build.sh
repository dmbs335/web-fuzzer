#!/bin/bash
# Build Go URL parser target
# Output: url_go_net_url binary (or url_go_net_url.exe on Windows)
set -e
cd "$(dirname "$0")"
echo "Building Go URL parser target..."
go build -o url_go_net_url.exe .
echo "Done: url_go_net_url.exe"
