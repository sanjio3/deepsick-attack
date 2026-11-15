#!/usr/bin/env python3
"""在没有 Docker daemon 的机器上拼出 `docker save` 格式的镜像 tar.gz。

Docker Desktop 服务未起、或 Docker Hub 不可达时 `build_image.sh` 不可用。
本脚本改为按 Registry V2 协议从可访问的镜像源拉取基础镜像的层，
再按 legacy `docker save` 归档布局组装出平台可直接导入的 .tar.gz：

    manifest.json
    <config-digest>.json
    <layer-id>/VERSION
    <layer-id>/json
    <layer-id>/layer.tar
    repositories

零第三方依赖，只用标准库。每一步都做自校验：基础层解压后的 sha256 必须
等于 config 里登记的 diff_id，否则直接报错退出，不产出坏镜像。

用法：
    python build_image_offline.py                 # 构建 dist/deepsick-attack-image.tar.gz
    python build_image_offline.py --verify-only   # 只校验已有产物结构
"""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------- 配置

BASE_IMAGE = "library/python"
BASE_TAG = "3.11-slim"
TARGET_ARCH = ("linux", "amd64")
IMAGE_TAG = "deepsick-attack:latest"
REPO_TAG = ("deepsick-attack", "latest")

# 按顺序尝试的镜像源，命中即用。都提供 library/python 的匿名拉取。
MIRRORS = [
    "docker.m.daocloud.io",
    "docker.1ms.run",
    "docker.1panel.live",
]

MANIFEST_ACCEPT = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist")
CACHE = os.path.join(DIST, ".image-cache")
OUTPUT = os.path.join(DIST, "deepsick-attack-image.tar.gz")

# 与 .dockerignore 对齐。命中即排除。
DEFAULT_EXCLUDES = [
    ".git", ".gitignore", ".dockerignore", ".env", ".editorconfig",
    "dist", "workspace", "ci-workspace", "__pycache__", ".image-cache",
    "*.pyc", "*.pyo", "*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.log",
]

# 容器内需要可执行的文件
EXECUTABLES = {"run.py", "build_image.sh", "build_image_offline.py",
               "nmap", "ncat", "socat", "busybox", "curl"}


def log(msg: str) -> None:
    print("[image] " + msg, flush=True)


# ---------------------------------------------------------------- Registry 客户端


class Registry:
    """最小可用的 Registry V2 只读客户端。"""

    def __init__(self, host: str, timeout: int = 60):
        self.host = host
        self.timeout = timeout
        self._token: str | None = None
        self._token_scope: str | None = None

    # -- 底层请求 --------------------------------------------------

    def _request(self, url: str, accept: str = MANIFEST_ACCEPT, auth: bool = True):
        headers = {"User-Agent": "docker/28.0.4", "Accept": accept}
        if auth and self._token:
            headers["Authorization"] = "Bearer " + self._token
        req = urllib.request.Request(url, headers=headers)
        return urllib.request.urlopen(req, timeout=self.timeout)

    def _fetch_token(self, repo: str) -> None:
        """走 WWW-Authenticate 挑战拿匿名 token。"""
        url = f"https://{self.host}/v2/{repo}/manifests/{BASE_TAG}"
        try:
            self._request(url, auth=False)
            self._token = None
            self._token_scope = repo
            return
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
            challenge = exc.headers.get("WWW-Authenticate", "")
        realm = re.search(r'realm="([^"]+)"', challenge)
        if not realm:
            raise RuntimeError(f"{self.host} 返回 401 但缺少 realm，无法取得 token")
        service = re.search(r'service="([^"]+)"', challenge)
        svc = service.group(1) if service else self.host
        token_url = f"{realm.group(1)}?service={svc}&scope=repository:{repo}:pull"
        payload = json.loads(self._request(token_url, auth=False).read())
        self._token = payload["token"]
        self._token_scope = repo

    def _ensure_token(self, repo: str) -> None:
        if self._token_scope != repo:
            self._fetch_token(repo)

    # -- 公开方法 --------------------------------------------------

    def ping(self) -> bool:
        try:
            with self._request(f"https://{self.host}/v2/", auth=False):
                return True
        except urllib.error.HTTPError as exc:
            return exc.code == 401
        except Exception:
            return False

    def get_json(self, path: str, repo: str) -> dict:
        self._ensure_token(repo)
        with self._request(f"https://{self.host}{path}") as resp:
            return json.loads(resp.read())

    def get_blob(self, repo: str, digest: str, dest: str) -> int:
        self._ensure_token(repo)
        if os.path.exists(dest):
            return os.path.getsize(dest)
        tmp = dest + ".part"
        with self._request(
            f"https://{self.host}/v2/{repo}/blobs/{digest}",
            accept="application/octet-stream",
        ) as resp, open(tmp, "wb") as fh:
            shutil.copyfileobj(resp, fh, 1024 * 256)
        os.replace(tmp, dest)
        return os.path.getsize(dest)


def pick_mirror() -> Registry:
    for host in MIRRORS:
        reg = Registry(host)
        if reg.ping():
            log(f"使用镜像源 {host}")
            return reg
        log(f"镜像源 {host} 不可达，换下一个")
    raise RuntimeError("所有镜像源都不可达，无法拉取基础镜像：" + ", ".join(MIRRORS))


def resolve_base(reg: Registry):
    """解析出 amd64/linux 的 config 与有序层列表，并下载到缓存。"""
    os.makedirs(CACHE, exist_ok=True)
    index = reg.get_json(f"/v2/{BASE_IMAGE}/manifests/{BASE_TAG}", BASE_IMAGE)

    entries = index.get("manifests")
    if not entries:  # 单平台镜像，本身就是 image manifest
        manifest, manifest_digest = index, None
    else:
        want_os, want_arch = TARGET_ARCH
        picked = None
        for item in entries:
            plat = item.get("platform") or {}
            if plat.get("os") == want_os and plat.get("architecture") == want_arch:
                picked = item
                break
        if picked is None:
            raise RuntimeError(f"{BASE_IMAGE}:{BASE_TAG} 没有 {want_os}/{want_arch} 平台")
        manifest = reg.get_json(
            f"/v2/{BASE_IMAGE}/manifests/{picked['digest']}", BASE_IMAGE
        )
        manifest_digest = picked["digest"]

    cfg_desc = manifest["config"]
    cfg_digest = cfg_desc["digest"]
    layers = manifest["layers"]

    cfg_path = os.path.join(CACHE, cfg_digest.replace(":", "_") + ".json")
    if not os.path.exists(cfg_path):
        reg.get_blob(BASE_IMAGE, cfg_digest, cfg_path)
    with open(cfg_path, "rb") as fh:
        config = json.loads(fh.read())

    diff_ids = config["rootfs"]["diff_ids"]
    if len(diff_ids) != len(layers):
        raise RuntimeError(
            f"config 登记 {len(diff_ids)} 层，manifest 列出 {len(layers)} 层，不一致"
        )

    log(f"基础镜像 {BASE_IMAGE}:{BASE_TAG} ({TARGET_ARCH[1]}) 共 {len(layers)} 层")
    layer_files = []
    for idx, layer in enumerate(layers):
        blob = os.path.join(CACHE, layer["digest"].replace(":", "_") + ".tar.gz")
        size = reg.get_blob(BASE_IMAGE, layer["digest"], blob)
        layer_files.append((blob, diff_ids[idx], size, str(layer.get("mediaType") or "")))
        log(f"  层 {idx + 1}/{len(layers)} {layer['digest'][7:19]} {size / 1048576:.1f} MB")
    return config, layer_files, manifest_digest


# ---------------------------------------------------------------- 应用层


def load_excludes() -> list[str]:
    path = os.path.join(ROOT, ".dockerignore")
    if not os.path.exists(path):
        return list(DEFAULT_EXCLUDES)
    patterns = list(DEFAULT_EXCLUDES)
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line.rstrip("/"))
    return patterns


def is_excluded(rel: str, patterns: list[str]) -> bool:
    parts = rel.split("/")
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(parts[0], pat):
            return True
        if fnmatch.fnmatch(os.path.basename(rel), pat):
            return True
    return False


def collect_app_files() -> list[tuple[str, str, int]]:
    """返回 (容器内路径, 本地路径, 权限) 列表，目录在前。"""
    patterns = load_excludes()
    dirs: list[tuple[str, str, int]] = []
    files: list[tuple[str, str, int]] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel_dir = os.path.relpath(dirpath, ROOT).replace(os.sep, "/")
        if rel_dir == ".":
            rel_dir = ""
        dirnames[:] = sorted(
            d for d in dirnames if not is_excluded(f"{rel_dir}/{d}".lstrip("/"), patterns)
        )
        if rel_dir:
            dirs.append(("app/" + rel_dir, dirpath, 0o755))
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}".lstrip("/")
            if is_excluded(rel, patterns):
                continue
            mode = 0o755 if name in EXECUTABLES else 0o644
            files.append(("app/" + rel, os.path.join(dirpath, name), mode))
    if not any(f[0] == "app/src/deepsick_attack/__main__.py" for f in files):
        raise RuntimeError("打包内容缺少 app/src/deepsick_attack/__main__.py，镜像不可运行")
    for item in files:
        if ".env" == os.path.basename(item[0]):
            raise RuntimeError("打包内容混入了 .env，拒绝继续（可能泄露密钥）")
    return [("app", ROOT, 0o755)] + dirs + files


def build_app_layer(config: dict) -> tuple[str, str]:
    """生成应用层 tar（未压缩），返回 (临时文件路径, diff_id)。"""
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    fd, path = tempfile.mkstemp(suffix=".tar", prefix="applayer-")
    os.close(fd)
    entries = collect_app_files()
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tar:
        for arcname, local, mode in entries:
            info = tarfile.TarInfo(arcname)
            info.mtime = int(time.time())
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = mode
            if os.path.isdir(local):
                info.type = tarfile.DIRTYPE
                info.size = 0
                tar.addfile(info)
            else:
                with open(local, "rb") as fh:
                    data = fh.read()
                info.type = tarfile.REGTYPE
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    digest = sha256_file(path)
    log(f"应用层 {len(entries)} 个条目，{os.path.getsize(path) / 1024:.1f} KB，diff_id {digest[:19]}")
    return path, "sha256:" + digest


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- 组装


def gunzip_to(src: str, dst: str) -> str:
    """解压基础层并校验其为合法 tar，返回 diff_id。"""
    with gzip.open(src, "rb") as zin, open(dst, "wb") as zout:
        shutil.copyfileobj(zin, zout, 1024 * 256)
    return "sha256:" + sha256_file(dst)


def write_tar_member(tar: tarfile.TarFile, arcname: str, data: bytes | None = None,
                     src: str | None = None, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(arcname)
    info.mtime = int(time.time())
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = mode
    if data is not None:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    else:
        size = os.path.getsize(src)
        info.size = size
        with open(src, "rb") as fh:
            tar.addfile(info, fh)


def assemble(config: dict, layer_files: list[tuple[str, str, int]],
             app_layer: str, app_diff_id: str) -> str:
    os.makedirs(DIST, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix="imgasm-")
    try:
        # 1. 基础层解压 + 校验
        prepared: list[tuple[str, str]] = []  # (layer.tar 路径, id)
        for idx, (blob, diff_id, _size, _mt) in enumerate(layer_files):
            plain = os.path.join(workdir, f"base-{idx}.tar")
            actual = gunzip_to(blob, plain)
            if actual != diff_id:
                raise RuntimeError(
                    f"基础层 {idx} 校验失败：manifest 登记 {diff_id}，实际 {actual}"
                )
            prepared.append((plain, diff_id[7:]))
        log("基础层 diff_id 全部校验通过")

        # 2. 追加应用层
        prepared.append((app_layer, app_diff_id[7:]))

        # 3. 新 image config
        cfg = json.loads(json.dumps(config))  # deep copy
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        env = cfg["config"].get("Env") or []
        for kv in ("PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1",
                   "PYTHONPATH=/app/src:/app/vendor/site-packages",
                   "PATH=/app/vendor/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"):
            key = kv.split("=")[0] + "="
            env = [e for e in env if not e.startswith(key)]
            env.append(kv)
        cfg["config"]["Env"] = env
        cfg["config"]["WorkingDir"] = "/app"
        cfg["config"]["Entrypoint"] = ["python", "-m", "deepsick_attack", "bench-solve"]
        cfg["config"]["Cmd"] = None
        cfg["created"] = created
        cfg["rootfs"]["diff_ids"] = [item[1] for item in layer_files] + [app_diff_id]
        cfg.setdefault("history", []).append({
            "created": created,
            "created_by": "build_image_offline.py",
            "comment": "app layer: deepsick-attack",
        })
        cfg_bytes = json.dumps(cfg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        cfg_name = hashlib.sha256(cfg_bytes).hexdigest() + ".json"
        log(f"image config {len(cfg_bytes)} 字节 -> {cfg_name[:19]}")

        # 4. 打包 legacy docker-save 布局
        manifest_layers = []
        tmp_out = OUTPUT + ".part"
        with tarfile.open(tmp_out, "w", format=tarfile.GNU_FORMAT) as tar:
            for idx, (layer_tar, layer_id) in enumerate(prepared):
                d = layer_id
                write_tar_member(tar, f"{d}/VERSION", data=b"1.0")
                legacy = {
                    "id": d,
                    "created": created,
                    "container_config": {"Env": env, "Cmd": ["/bin/sh", "-c", "#(nop)"]},
                    "os": "linux",
                }
                if idx > 0:
                    legacy["parent"] = prepared[idx - 1][1]
                write_tar_member(
                    tar, f"{d}/json",
                    data=json.dumps(legacy, separators=(",", ":")).encode("utf-8"),
                )
                write_tar_member(tar, f"{d}/layer.tar", src=layer_tar, mode=0o644)
                manifest_layers.append(f"{d}/layer.tar")
                log(f"  归档层 {idx + 1}/{len(prepared)} -> {d[:19]}")

            write_tar_member(tar, cfg_name, data=cfg_bytes)

            manifest = [{
                "Config": cfg_name,
                "RepoTags": [IMAGE_TAG],
                "Layers": manifest_layers,
            }]
            write_tar_member(
                tar, "manifest.json",
                data=json.dumps(manifest, separators=(",", ":")).encode("utf-8"),
            )
            repos = {REPO_TAG[0]: {REPO_TAG[1]: prepared[-1][1]}}
            write_tar_member(
                tar, "repositories",
                data=json.dumps(repos, separators=(",", ":")).encode("utf-8"),
            )
        os.replace(tmp_out, OUTPUT + ".tar.tmp")
        log("外层归档完成，开始压缩")
        with open(OUTPUT + ".tar.tmp", "rb") as src, \
                gzip.open(OUTPUT, "wb", compresslevel=6) as dst:
            shutil.copyfileobj(src, dst, 1024 * 256)
        os.remove(OUTPUT + ".tar.tmp")
        return OUTPUT
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------- OCI 归档

OCI_OUTPUT = os.path.join(DIST, "deepsick-attack-image-oci.tar.gz")

# 平台侧按 OCI 规范校验（oci-layout + index.json），基础层的 docker 媒体类型统一换成 OCI 的。
LAYER_MEDIA_MAP = {
    "application/vnd.docker.image.rootfs.diff.tar.gzip":
        "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
}
OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"


def _norm_layer_media(media_type: str) -> str:
    return LAYER_MEDIA_MAP.get(media_type or "", media_type or OCI_LAYER_GZIP)


def _image_config(config: dict, diff_ids: list[str]) -> bytes:
    """在原基础镜像 config 上叠加应用层与环境，返回序列化后的字节。"""
    cfg = json.loads(json.dumps(config))
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    env = cfg["config"].get("Env") or []
    for kv in ("PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1",
               "PYTHONPATH=/app/src:/app/vendor/site-packages",
               "PATH=/app/vendor/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"):
        prefix = kv.split("=")[0] + "="
        env = [e for e in env if not e.startswith(prefix)]
        env.append(kv)
    cfg["config"]["Env"] = env
    cfg["config"]["WorkingDir"] = "/app"
    cfg["config"]["Entrypoint"] = ["python", "-m", "deepsick_attack", "bench-solve"]
    cfg["config"]["Cmd"] = None
    cfg["created"] = created
    cfg["rootfs"]["diff_ids"] = list(diff_ids)
    cfg.setdefault("history", []).append({
        "created": created,
        "created_by": "build_image_offline.py",
        "comment": "app layer: deepsick-attack",
    })
    return json.dumps(cfg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def assemble_oci(config: dict, layer_files: list, app_layer_tar: str,
                 app_diff_id: str, arch: str = "amd64", os_name: str = "linux") -> str:
    """按 OCI Image Layout 组装 tar.gz：oci-layout / index.json / blobs/sha256/*。"""
    os.makedirs(DIST, exist_ok=True)
    work = tempfile.mkdtemp(prefix="ociasm-")
    try:
        blobs: dict[str, str] = {}
        layer_desc = []

        # 1. 基础层：镜像源给的已经是 gzip blob，digest 就是压缩后的 sha256，直接复用
        for blob_path, diff_id, size, media in layer_files:
            digest = sha256_file(blob_path)
            blobs[digest] = blob_path
            layer_desc.append({
                "mediaType": _norm_layer_media(media),
                "digest": "sha256:" + digest,
                "size": size,
            })
        log(f"OCI 基础层 {len(layer_desc)} 个")

        # 2. 应用层压成 gzip blob
        app_gz = os.path.join(work, "app.tar.gz")
        with open(app_layer_tar, "rb") as src, \
                gzip.open(app_gz, "wb", compresslevel=6) as dst:
            shutil.copyfileobj(src, dst, 1024 * 256)
        app_digest = sha256_file(app_gz)
        app_size = os.path.getsize(app_gz)
        blobs[app_digest] = app_gz
        layer_desc.append({"mediaType": OCI_LAYER_GZIP,
                           "digest": "sha256:" + app_digest, "size": app_size})
        log(f"OCI 应用层 {app_size / 1024:.1f} KB")

        # 3. config blob
        diff_ids = [item[1] for item in layer_files] + [app_diff_id]
        cfg_bytes = _image_config(config, diff_ids)
        cfg_digest = hashlib.sha256(cfg_bytes).hexdigest()
        cfg_path = os.path.join(work, "config.json")
        with open(cfg_path, "wb") as fh:
            fh.write(cfg_bytes)
        blobs[cfg_digest] = cfg_path

        # 4. image manifest
        manifest = {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {"mediaType": OCI_CONFIG,
                       "digest": "sha256:" + cfg_digest,
                       "size": len(cfg_bytes)},
            "layers": layer_desc,
        }
        man_bytes = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
        man_digest = hashlib.sha256(man_bytes).hexdigest()
        man_path = os.path.join(work, "manifest.json")
        with open(man_path, "wb") as fh:
            fh.write(man_bytes)
        blobs[man_digest] = man_path

        # 5. index.json
        index = {
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": [{
                "mediaType": OCI_MANIFEST,
                "digest": "sha256:" + man_digest,
                "size": len(man_bytes),
                "platform": {"architecture": arch, "os": os_name},
                "annotations": {"org.opencontainers.image.ref.name": IMAGE_TAG},
            }],
        }

        # 6. 打成 tar.gz
        tmp_out = OCI_OUTPUT + ".tmp"
        with tarfile.open(tmp_out, "w", format=tarfile.GNU_FORMAT) as tar:
            write_tar_member(tar, "oci-layout",
                             data=json.dumps({"imageLayoutVersion": "1.0.0"},
                                             separators=(",", ":")).encode())
            write_tar_member(tar, "index.json",
                             data=json.dumps(index, separators=(",", ":")).encode())
            for digest, src in blobs.items():
                write_tar_member(tar, f"blobs/sha256/{digest}", src=src, mode=0o644)
        log(f"OCI 归档完成，{len(blobs)} 个 blob，开始压缩")
        with open(tmp_out, "rb") as src, gzip.open(OCI_OUTPUT, "wb", compresslevel=6) as dst:
            shutil.copyfileobj(src, dst, 1024 * 256)
        os.remove(tmp_out)
        return OCI_OUTPUT
    finally:
        shutil.rmtree(work, ignore_errors=True)


def verify_oci(path: str) -> bool:
    """按 OCI 规范复检：index → manifest → config → 每层 digest 与 diff_id。"""
    log(f"校验（OCI）{os.path.basename(path)}")
    ok = True
    with tarfile.open(path, "r:gz") as tar:
        names = set(tar.getnames())
        for required in ("oci-layout", "index.json"):
            if required not in names:
                log(f"  [FAIL] 缺少 {required}")
                return False
        layout = json.loads(tar.extractfile("oci-layout").read())
        if layout.get("imageLayoutVersion") != "1.0.0":
            log(f"  [FAIL] oci-layout 版本异常 {layout}")
            ok = False
        index = json.loads(tar.extractfile("index.json").read())
        if not index.get("manifests"):
            log("  [FAIL] index.json 没有 manifests")
            return False
        entry = index["manifests"][0]
        man_digest = entry["digest"].split(":", 1)[1]
        man_name = f"blobs/sha256/{man_digest}"
        if man_name not in names:
            log(f"  [FAIL] index 指向的 manifest 不在包里：{man_name}")
            return False
        man_bytes = tar.extractfile(man_name).read()
        if hashlib.sha256(man_bytes).hexdigest() != man_digest:
            log("  [FAIL] manifest digest 与内容不符")
            ok = False
        manifest = json.loads(man_bytes)
        cfg_digest = manifest["config"]["digest"].split(":", 1)[1]
        cfg_name = f"blobs/sha256/{cfg_digest}"
        if cfg_name not in names:
            log(f"  [FAIL] 缺少 config blob {cfg_name}")
            return False
        cfg_bytes = tar.extractfile(cfg_name).read()
        if hashlib.sha256(cfg_bytes).hexdigest() != cfg_digest:
            log("  [FAIL] config digest 与内容不符")
            ok = False
        cfg = json.loads(cfg_bytes)
        layers = manifest["layers"]
        diff_ids = cfg["rootfs"]["diff_ids"]
        if len(layers) != len(diff_ids):
            log(f"  [FAIL] layers {len(layers)} vs diff_ids {len(diff_ids)}")
            return False
        for i, layer in enumerate(layers):
            d = layer["digest"].split(":", 1)[1]
            name = f"blobs/sha256/{d}"
            if name not in names:
                log(f"  [FAIL] 缺少层 blob {name}")
                ok = False
                continue
            blob = tar.extractfile(name).read()
            if hashlib.sha256(blob).hexdigest() != d:
                log(f"  [FAIL] 层 {i} 压缩后 digest 不符")
                ok = False
            plain = gzip.decompress(blob)
            if "sha256:" + hashlib.sha256(plain).hexdigest() != diff_ids[i]:
                log(f"  [FAIL] 层 {i} 解压后 diff_id 不符")
                ok = False
        c = cfg.get("config", {})
        if c.get("Entrypoint") != ["python", "-m", "deepsick_attack", "bench-solve"]:
            log(f"  [FAIL] Entrypoint 异常 {c.get('Entrypoint')}")
            ok = False
        if c.get("WorkingDir") != "/app":
            log(f"  [FAIL] WorkingDir 异常 {c.get('WorkingDir')}")
            ok = False
        if "PYTHONPATH=/app/src:/app/vendor/site-packages" not in (c.get("Env") or []):
            log("  [FAIL] 缺少 PYTHONPATH=/app/src:/app/vendor/site-packages")
            ok = False
        app_name = f"blobs/sha256/{layers[-1]['digest'].split(':', 1)[1]}"
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(tar.extractfile(app_name).read())),
                          mode="r:") as app:
            members = app.getnames()
        if not any(m.rstrip("/") == "app/src/deepsick_attack/__main__.py" for m in members):
            log("  [FAIL] 应用层缺少 src/deepsick_attack/__main__.py")
            ok = False
        if any(os.path.basename(m.rstrip("/")) == ".env" for m in members):
            log("  [FAIL] 应用层混入 .env，可能泄露密钥")
            ok = False
        log(f"  OCI 层数 {len(layers)}，架构 {cfg.get('architecture')}/{cfg.get('os')}")
    log(f"  体积 {os.path.getsize(path) / 1048576:.1f} MB，sha256 {sha256_file(path)}")
    return ok

# ---------------------------------------------------------------- 校验


def verify(path: str) -> bool:
    """把产物当消费者重新读一遍：结构、层 diff_id、入口点。"""
    log(f"校验 {os.path.basename(path)}")
    ok = True
    with tarfile.open(path, "r:gz") as tar:
        names = set(tar.getnames())
        if "manifest.json" not in names:
            log("  [FAIL] 缺少 manifest.json")
            return False
        manifest = json.loads(tar.extractfile("manifest.json").read())
        entry = manifest[0]
        cfg_name = entry["Config"]
        if cfg_name not in names:
            log(f"  [FAIL] 缺少 config {cfg_name}")
            return False
        cfg_bytes = tar.extractfile(cfg_name).read()
        cfg = json.loads(cfg_bytes)
        expect = hashlib.sha256(cfg_bytes).hexdigest() + ".json"
        if expect != cfg_name:
            log(f"  [FAIL] config 文件名与内容摘要不符：期望 {expect}")
            ok = False
        diff_ids = cfg["rootfs"]["diff_ids"]
        layers = entry["Layers"]
        if len(diff_ids) != len(layers):
            log(f"  [FAIL] diff_ids {len(diff_ids)} 个 vs Layers {len(layers)} 个")
            return False
        for i, lay in enumerate(layers):
            if lay not in names:
                log(f"  [FAIL] 缺少层文件 {lay}")
                ok = False
                continue
            digest = hashlib.sha256()
            with tar.extractfile(lay) as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            if "sha256:" + digest.hexdigest() != diff_ids[i]:
                log(f"  [FAIL] 层 {i} diff_id 不匹配")
                ok = False
        c = cfg.get("config", {})
        if c.get("Entrypoint") != ["python", "-m", "deepsick_attack", "bench-solve"]:
            log(f"  [FAIL] Entrypoint 异常：{c.get('Entrypoint')}")
            ok = False
        if c.get("WorkingDir") != "/app":
            log(f"  [FAIL] WorkingDir 异常：{c.get('WorkingDir')}")
            ok = False
        env = c.get("Env") or []
        if "PYTHONPATH=/app/src:/app/vendor/site-packages" not in env:
            log("  [FAIL] 缺少 PYTHONPATH=/app/src:/app/vendor/site-packages")
            ok = False
        # 确认应用层里确实有包
        app_layer = layers[-1]
        inner = tar.extractfile(app_layer)
        found_main = False
        found_env = False
        with tarfile.open(fileobj=inner, mode="r:") as app:
            for m in app.getmembers():
                if m.name in ("app/src/deepsick_attack/__main__.py", "./app/src/deepsick_attack/__main__.py"):
                    found_main = True
                if os.path.basename(m.name) == ".env":
                    found_env = True
        if not found_main:
            log("  [FAIL] 应用层缺少 src/deepsick_attack/__main__.py")
            ok = False
        if found_env:
            log("  [FAIL] 应用层混入 .env，可能泄露密钥")
            ok = False
        log(f"  镜像层数 {len(layers)}，架构 {cfg.get('architecture')}/{cfg.get('os')}")
    size = os.path.getsize(path)
    log(f"  体积 {size / 1048576:.1f} MB，sha256 {sha256_file(path)}")
    return ok


# ---------------------------------------------------------------- 入口


def ensure_vendor() -> None:
    """确保 vendor/site-packages 已由轮子解包出来。

    依赖以 manylinux 轮子随源码入库，解包是纯文件操作（zipfile），不需要 pip
    也不需要网络，所以能进零 daemon 的构建路径。
    """
    target = os.path.join(ROOT, "vendor", "site-packages")
    marker = os.path.join(target, "paramiko", "__init__.py")
    if os.path.exists(marker):
        return
    script = os.path.join(ROOT, "vendor", "install_vendor.py")
    if not os.path.exists(script):
        log("警告：vendor/install_vendor.py 不存在，镜像内将没有 SSH/DNS 依赖")
        return
    log("解包 vendor 依赖")
    result = subprocess.run([sys.executable, script], cwd=ROOT)
    if result.returncode != 0:
        log("警告：vendor 依赖解包失败，SSH/DNS 分支会降级")


def main() -> int:
    parser = argparse.ArgumentParser(description="不依赖 Docker daemon 构建镜像 tar.gz")
    parser.add_argument("--format", choices=["oci", "docker"], default="oci",
                        help="oci: OCI Image Layout（平台托管评测要求）；docker: docker save 布局")
    parser.add_argument("--verify-only", action="store_true", help="只校验已有产物")
    parser.add_argument("--keep-cache", action="store_true", help="保留已下载的基础层")
    args = parser.parse_args()

    socket.setdefaulttimeout(60)

    if args.verify_only:
        target = OCI_OUTPUT if args.format == "oci" else OUTPUT
        if not os.path.exists(target):
            log(f"产物不存在：{target}")
            return 2
        return 0 if (verify_oci(target) if args.format == "oci" else verify(target)) else 1

    log(f"基线：不使用 Docker daemon，按 Registry V2 + {'OCI Image Layout' if args.format == 'oci' else 'docker-save 布局'}组装")

    ensure_vendor()

    reg = pick_mirror()
    config, layer_files, base_digest = resolve_base(reg)
    log(f"基础镜像 digest {base_digest}")

    app_layer, app_diff_id = build_app_layer(config)
    try:
        if args.format == "oci":
            out = assemble_oci(config, layer_files, app_layer, app_diff_id)
        else:
            out = assemble(config, layer_files, app_layer, app_diff_id)
    finally:
        if os.path.exists(app_layer):
            os.remove(app_layer)

    passed = verify_oci(out) if args.format == "oci" else verify(out)
    if not passed:
        log("校验未通过，产物不可用")
        return 1

    if not args.keep_cache:
        shutil.rmtree(CACHE, ignore_errors=True)
    log(f"完成：{out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
