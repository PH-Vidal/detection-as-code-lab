FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --gid 10001 dacgroup \
    && useradd --uid 10001 --gid 10001 --shell /usr/sbin/nologin --create-home dacuser

COPY pyproject.toml README.md LICENSE ./
COPY detection_engine/ ./detection_engine/
COPY simulator/ ./simulator/
COPY rules/ ./rules/
COPY threat_intel/ ./threat_intel/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[yaml]" \
    && mkdir -p /app/lab_output \
    && chown -R 10001:10001 /app

USER 10001

ENTRYPOINT ["dac-lab"]
CMD ["run-lab", "--output-dir", "/app/lab_output"]
