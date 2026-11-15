FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app
COPY . /app

# 平台在创建跑分任务后自动注入 BENCHMARK_TOKEN 与 BENCHMARK_BASE_URL。
# 模型凭据通过环境变量 MINIMAX_API_KEY / MINIMAX_BASE_URL 注入，
# 不写入镜像；.dockerignore 已排除 .env 与所有运行产物。
# 平台适配层与模型客户端都是标准库实现，不需要 pip 安装依赖。

ENTRYPOINT ["python", "-m", "deepsick_attack", "bench-solve"]
