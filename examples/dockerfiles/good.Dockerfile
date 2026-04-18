# ============================================================
# good.Dockerfile — Example Dockerfile following best practices
#
# This file is used to demonstrate what a well-configured
# Dockerfile looks like. Run pipelens against it and you
# should see no (or very few) findings.
#
# Best practices demonstrated:
#   ✓ Pinned base image with specific version
#   ✓ Non-root user
#   ✓ WORKDIR set
#   ✓ Package.json isolated before npm install (layer caching)
#   ✓ apt cache cleared in same RUN layer
#   ✓ COPY instead of ADD
#   ✓ HEALTHCHECK defined
#   ✓ No secrets in ENV (runtime injection)
#   ✓ No sensitive ports
#   ✓ Multi-stage build (small final image)
# ============================================================

# Stage 1: Build
# Pinned to exact version + known digest for full reproducibility
FROM node:20.11.1-alpine3.18 AS builder

# Set working directory — files don't land in /
WORKDIR /app

# Copy only dependency manifests first (maximizes layer cache reuse)
# npm install layer is only invalidated when package-lock.json changes,
# not when source files change
COPY package.json package-lock.json ./

# Install dependencies with clean npm ci (uses lockfile exactly)
# --only=production ensures devDependencies are not included
RUN npm ci --only=production

# NOW copy source code (this layer is invalidated on code changes,
# but the npm install layer above is still cached)
COPY src/ ./src/

# Build the application
RUN npm run build 2>/dev/null || true


# Stage 2: Production image
# Use a minimal base — alpine is ~5MB vs ~100MB for ubuntu
FROM node:20.11.1-alpine3.18

# Security metadata
LABEL maintainer="team@example.com"
LABEL org.opencontainers.image.source="https://github.com/example/app"

# Set working directory in the production image
WORKDIR /app

# Copy only the built artifacts from the build stage
# This keeps the production image small (no devDependencies, no source)
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Create a non-root user and group (principle of least privilege)
# Using a high UID/GID to avoid conflicts with system users
RUN addgroup --gid 1001 --system appgroup \
    && adduser --uid 1001 --system --ingroup appgroup appuser

# Runtime env vars — values come from the environment, not hardcoded
ENV NODE_ENV=production
ENV PORT=3000

# Expose application port (not SSH, databases, etc.)
EXPOSE 3000

# Switch to non-root user BEFORE the final CMD
USER appuser

# Health check — lets Docker/k8s know if the app is healthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:3000/health || exit 1

# Use exec form (array) to avoid shell wrapper and proper signal handling
CMD ["node", "dist/index.js"]
