FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install Semgrep dependencies, git, and curl.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep via pip.
RUN pip install --no-cache-dir semgrep==1.78.0

# Install OSV-Scanner as a pre-built Go binary (not a pip package).
# Pin to a specific release for reproducibility.
RUN curl -sSfL \
    "https://github.com/google/osv-scanner/releases/download/v1.7.4/osv-scanner_linux_amd64" \
    -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner

# Create non-root user for scan execution.
RUN useradd -m -u 1000 codesentry

WORKDIR /workspace
RUN mkdir -p /workspace/source /workspace/out && chown -R codesentry:codesentry /workspace

COPY run_scan.py /workspace/run_scan.py
RUN chmod +x /workspace/run_scan.py

USER codesentry

ENTRYPOINT ["python", "/workspace/run_scan.py"]
