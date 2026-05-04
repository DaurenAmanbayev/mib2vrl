FROM timberio/vector:latest-alpine AS vector-base
FROM python:3.11-slim

LABEL maintainer="mib2vrl"
LABEL description="SNMP MIB to Vector.dev VRL converter"

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml .
COPY mib2vrl/ ./mib2vrl/

# Install package
RUN pip install --no-cache-dir -e .

# Output directory for generated configs
RUN mkdir -p /app/out /app/mibs

VOLUME ["/app/mibs", "/app/out"]

ENTRYPOINT ["mib2vrl"]
CMD ["--help"]
