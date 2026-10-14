# Supply Chain Sentinel -- eBPF Monitoring Agent
# Requires: Docker with --privileged flag, host Linux kernel >= 4.9
# Mounts: /sys, /proc, /lib/modules, /usr/src (kernel headers)
FROM ubuntu:22.04

LABEL maintainer="Supply Chain Sentinel"
LABEL description="eBPF-based kernel monitoring agent for container security"
LABEL version="1.0.0"

ARG DEBIAN_FRONTEND=noninteractive

# Install BCC and kernel tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools \
    linux-headers-generic \
    python3-bpfcc \
    python3-pip \
    python3.11 \
    python3.11-dev \
    libelf-dev \
    clang \
    llvm \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3.11 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1

WORKDIR /sentinel-agent

# Copy agent files
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY agent.py .
COPY probe_programs/ ./probe_programs/

# The agent needs privileged access to load eBPF programs
# This is set at docker run time, not in Dockerfile
# docker run --privileged --pid=host --net=host \
#   -v /sys:/sys:ro -v /proc:/proc:ro \
#   -v /lib/modules:/lib/modules:ro \
#   -v /usr/src:/usr/src:ro \
#   sentinel-agent

ENTRYPOINT ["python3", "agent.py"]
CMD ["--help"]
