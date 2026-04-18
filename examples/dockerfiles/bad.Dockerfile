# ============================================================
# bad.Dockerfile — Example Dockerfile with intentional issues
#
# This file is used to test and demonstrate pipelens detections.
# Run: pipelens audit --dockerfile examples/dockerfiles/bad.Dockerfile
#
# Issues present (see comments):
#   DF-SEC-001: No USER instruction (runs as root)
#   DF-SEC-002: Hardcoded credentials in ENV
#   DF-SEC-003: curl piped into bash
#   DF-SEC-004: SSH port exposed
#   DF-BP-001:  Unpinned :latest base image
#   DF-BP-002:  ADD used instead of COPY
#   DF-BP-003:  No HEALTHCHECK
#   DF-BP-005:  No WORKDIR
#   DF-LAYER-001: apt cache not cleared
#   DF-LAYER-003: Source copied before npm install
#   DF-LAYER-004: No isolated package.json COPY
# ============================================================

# DF-BP-001: Using :latest tag — non-reproducible
FROM ubuntu:latest

# DF-SEC-002: Hardcoded credentials — never do this!
ENV DB_PASSWORD=supersecret123
ENV API_KEY=sk-abc123def456ghi789jkl012mno345pq

# DF-LAYER-001: apt cache not cleared in same layer
RUN apt-get update && apt-get install -y curl wget git nodejs npm

# DF-SEC-003: Dangerous pipe to bash — no checksum verification
RUN curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# DF-BP-002: ADD used instead of COPY (no URL, no tar)
ADD . /app

# DF-LAYER-003 & DF-LAYER-004: Source copied before npm install
# Any source change invalidates npm install cache
RUN npm install

# DF-SEC-004: SSH port is a security risk in containers
EXPOSE 22

EXPOSE 3000

# DF-SEC-001: No USER instruction — runs as root
# DF-BP-003: No HEALTHCHECK
CMD ["node", "/app/index.js"]
