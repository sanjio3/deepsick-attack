#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

docker build -t deepsick-attack:latest .
mkdir -p dist
docker save deepsick-attack:latest | gzip > dist/deepsick-attack-image.tar.gz

echo "written: dist/deepsick-attack-image.tar.gz"
ls -lh dist/deepsick-attack-image.tar.gz
