# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Deterministic, log-friendly Python behaviour inside the container.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SIFT_HOST=0.0.0.0 \
    SIFT_PORT=5150

WORKDIR /app

# Install dependencies first so the layer is cached across source-only changes.
COPY requirements.txt pyproject.toml ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the source and install the siftprotocols package.
COPY . .
RUN pip install -e .

EXPOSE 5150

# The entrypoint generates a fresh RSA-2048 key pair on first boot IF none is
# already present (e.g. mounted from a volume/secret). In a real deployment,
# mount a persistent, out-of-band-distributed key at /app/server/keys instead
# of relying on an ephemeral per-container key -- see docker-compose.yml.
#
# `sh -c '... exec "$@"' --` runs the bootstrap, then execs whatever command is
# passed (the CMD below, or an override such as the webdemo service in compose).
ENTRYPOINT ["sh", "-c", "if [ ! -f server/keys/private_key.pem ]; then echo 'No server key found -- generating a fresh RSA-2048 key pair'; python generate_keys.py; fi; exec \"$@\"", "--"]

# Default: run the SiFT server bound to all interfaces on 5150.
CMD ["sh", "-c", "python server/server.py --host \"$SIFT_HOST\" --port \"$SIFT_PORT\""]
