#!/bin/bash
# Build C# URL parser target
# Requires: .NET 8.0 SDK
set -e
cd "$(dirname "$0")"
echo "Building C# URL parser target..."
dotnet publish -c Release -o bin/
echo "Done: bin/url_dotnet_uri.exe"
