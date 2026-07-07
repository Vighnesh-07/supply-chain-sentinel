# ============================================================
# Nexus Studio - Production Dockerfile
# Build context: supply-chain-sentinel/ (project root)
# Usage: docker build -f demo-apps/nexus-studio/Dockerfile -t nexus-studio-app .
# ============================================================

FROM node:20-alpine

WORKDIR /app

# Install Python so the data-stealer (Python) package is present
# in the container for multi-language runtime scanning
RUN apk add --no-cache python3 py3-pip

# Copy ALL local demo package dependencies
COPY demo-packages/nexus-formatter /demo-packages/nexus-formatter
COPY demo-packages/cloud-exfil     /demo-packages/cloud-exfil
COPY demo-packages/crypt-loader    /demo-packages/crypt-loader
COPY demo-packages/data-stealer    /demo-packages/data-stealer
COPY demo-packages/wallet-drainer  /demo-packages/wallet-drainer
COPY demo-packages/env-harvester  /demo-packages/env-harvester
COPY demo-packages/hex-beacon      /demo-packages/hex-beacon
COPY demo-packages/b64-dropper     /demo-packages/b64-dropper
COPY demo-packages/cmd-implant     /demo-packages/cmd-implant
COPY demo-packages/fs-backdoor     /demo-packages/fs-backdoor
COPY demo-packages/webhook-spy     /demo-packages/webhook-spy
COPY demo-packages/net-phantom     /demo-packages/net-phantom

# Copy app source
COPY demo-apps/nexus-studio/package.json ./
COPY demo-apps/nexus-studio/server.js ./
COPY demo-apps/nexus-studio/preload.cjs ./
COPY demo-apps/nexus-studio/vite.config.js ./
COPY demo-apps/nexus-studio/index.html ./
COPY demo-apps/nexus-studio/src ./src

# Fix the file: reference paths for Docker context
RUN sed -i 's|file:../../demo-packages/nexus-formatter|file:/demo-packages/nexus-formatter|' package.json && \
    sed -i 's|file:../../demo-packages/cloud-exfil|file:/demo-packages/cloud-exfil|' package.json && \
    sed -i 's|file:../../demo-packages/crypt-loader|file:/demo-packages/crypt-loader|' package.json && \
    sed -i 's|file:../../demo-packages/wallet-drainer|file:/demo-packages/wallet-drainer|' package.json && \
    sed -i 's|file:../../demo-packages/env-harvester|file:/demo-packages/env-harvester|' package.json && \
    sed -i 's|file:../../demo-packages/hex-beacon|file:/demo-packages/hex-beacon|' package.json && \
    sed -i 's|file:../../demo-packages/b64-dropper|file:/demo-packages/b64-dropper|' package.json && \
    sed -i 's|file:../../demo-packages/cmd-implant|file:/demo-packages/cmd-implant|' package.json && \
    sed -i 's|file:../../demo-packages/fs-backdoor|file:/demo-packages/fs-backdoor|' package.json && \
    sed -i 's|file:../../demo-packages/webhook-spy|file:/demo-packages/webhook-spy|' package.json && \
    sed -i 's|file:../../demo-packages/net-phantom|file:/demo-packages/net-phantom|' package.json

# Install npm dependencies (includes nexus-formatter, cloud-exfil, crypt-loader)
# --ignore-scripts prevents the malicious preinstall/postinstall hooks from running
RUN npm install --ignore-scripts

# Install the Python data-stealer package into the container
RUN pip install --break-system-packages /demo-packages/data-stealer/ 2>/dev/null || true

# Build the Vite frontend
RUN npx vite build

EXPOSE 3000

# Enable the Supply Chain Sentinel attribution preload.
# This monkey-patches http/https/net to log which package
# initiated each outbound connection (writes to /app/network_attribution.log).
ENV NODE_OPTIONS="--require /app/preload.cjs"

CMD ["node", "server.js"]
