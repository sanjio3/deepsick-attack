"""把 vendor/wheels 下的 manylinux 轮子解包进 vendor/site-packages。

为什么不 pip install：镜像由 build_image_offline.py 零 daemon 组装，构建阶段没有
可执行的 pip；而平台沙箱里也不能联网。所以依赖以「纯文件」形态随镜像走，
只把 vendor/site-packages 加进 PYTHONPATH，运行期 import 即可。

轮子必须是 manylinux x86_64 + cp311（基础镜像 python:3.11-slim 的 ABI）。
重新取轮子的命令见 README。
"""
from __future__ import annotations

import pathlib
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
WHEELS = ROOT / "wheels"
TARGET = ROOT / "site-packages"
# 只解包这些顶层包，避免把 .dist-info 和脚本塞进镜像
PACKAGES = ("paramiko", "cryptography", "bcrypt", "nacl", "cffi", "pycparser",
            "dns", "_cffi_backend")


def main() -> int:
    wheels = sorted(WHEELS.glob("*.whl"))
    if not wheels:
        print(f"没有找到轮子：{WHEELS}", file=sys.stderr)
        return 1
    TARGET.mkdir(parents=True, exist_ok=True)
    total = 0
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if name.endswith("/"):
                    continue
                if not name.startswith(PACKAGES):
                    continue
                path = TARGET / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.read(name))
                total += 1
        print(f"[vendor] {wheel.name}")
    print(f"[vendor] {total} 个文件 → {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
