FROM python:3.13-slim

# Runs as an unprivileged user, read only filesystem friendly, no build tools left behind.
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY pyproject.toml README.md ./
COPY fedramp_viz ./fedramp_viz
RUN pip install --no-cache-dir ".[azure]" && rm -rf /root/.cache

USER app
ENV FEDRAMP_VIZ_SOURCE=/data/inventory.json \
    FEDRAMP_VIZ_HOST=0.0.0.0 \
    FEDRAMP_VIZ_PORT=8080
EXPOSE 8080
# Mount an exported inventory at /data/inventory.json, or set FEDRAMP_VIZ_SOURCE=azure
# and provide credentials through the environment (AZURE_CLIENT_ID and friends, or a
# workload identity). Set FEDRAMP_VIZ_TOKEN to require a bearer token on the API.
CMD ["sh", "-c", "fedramp-viz serve --source \"$FEDRAMP_VIZ_SOURCE\" --host \"$FEDRAMP_VIZ_HOST\" --port \"$FEDRAMP_VIZ_PORT\""]
