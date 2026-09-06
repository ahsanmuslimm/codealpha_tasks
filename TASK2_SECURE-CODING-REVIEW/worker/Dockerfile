FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install Semgrep, OSV-Scanner, and git.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir semgrep==1.78.0 osv-scanner==1.7.4

# Create non-root user for scan execution.
RUN useradd -m -u 1000 codesentry

WORKDIR /workspace
RUN mkdir -p /workspace/source /workspace/out && chown -R codesentry:codesentry /workspace

COPY run_scan.py /workspace/run_scan.py
RUN chmod +x /workspace/run_scan.py

USER codesentry

ENTRYPOINT ["python", "/workspace/run_scan.py"]
