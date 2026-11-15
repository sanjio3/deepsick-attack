#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p dist

# 平台只接受 OCI Image Layout（oci-layout + index.json + blobs/sha256/*）。
# docker save 产出的 legacy 布局会被拒：app_dist is not a valid OCI image archive。
OUT=dist/deepsick-attack-image-oci.tar.gz

if docker buildx version >/dev/null 2>&1; then
  docker buildx build --output type=oci,dest=dist/deepsick-attack-image-oci.tar \
    -t deepsick-attack:latest .
  gzip -c dist/deepsick-attack-image-oci.tar > "$OUT"
  rm -f dist/deepsick-attack-image-oci.tar
else
  echo "buildx 不可用，退回离线构建器（零 daemon，效果等价）" >&2
  python build_image_offline.py --format oci
fi

echo "written: $OUT"
ls -lh "$OUT"
sha256sum "$OUT" 2>/dev/null || shasum -a 256 "$OUT"
