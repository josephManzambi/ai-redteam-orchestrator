FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /scan-target
COPY poisoned-demo-server.py mcp_scan_client.json ./
CMD ["bash"]
