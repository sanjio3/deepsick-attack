FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src:/app/vendor/site-packages

WORKDIR /app
COPY . /app

# 依赖以 manylinux 轮子的形态随源码走，构建期解包成纯文件目录，不进 pip、不联网。
# 有网也可以用 vendor/wheels 里同样的轮子离线安装；这里解包是为了零 daemon 构建
# 与 Docker 构建产出一致。
RUN python vendor/install_vendor.py

# 平台在创建跑分任务后自动注入 BENCHMARK_TOKEN 与 BENCHMARK_BASE_URL。
# 模型凭据通过环境变量 MINIMAX_API_KEY / MINIMAX_BASE_URL 注入，
# 不写入镜像；.dockerignore 已排除 .env 与所有运行产物。

ENTRYPOINT ["python", "-m", "deepsick_attack", "bench-solve"]
