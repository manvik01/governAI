# ZenAi4 gateway - one stateless container; all state lives in the /data volume.
#
#   docker build -t zenai4:local .
#   docker compose up -d                         (see compose.yaml and docs/deployment)
#   docker compose exec gateway zenai4-admin init --admin-email you@company.com --admin-name "You"
#
# Single node only while the stores are on SQLite. More than one replica needs the
# Postgres + Redis work in milestone M4 (docs/PRD.md section 10).

ARG NODE_IMAGE=node:22-bookworm
ARG NODE_RUNTIME_IMAGE=node:22-bookworm-slim

# ---- build: compile TypeScript and the native SQLite driver
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build \
 && npm prune --omit=dev \
 && rm -f dist/*/*.test.js dist/budget/race-worker.js \
 && chmod 0755 dist/control/admin-cli.js

# ---- runtime: no compiler, no dev dependencies, non-root
FROM ${NODE_RUNTIME_IMAGE}
LABEL org.opencontainers.image.title="ZenAi4 gateway" \
      org.opencontainers.image.description="Governance control plane for AI agents" \
      org.opencontainers.image.source="https://github.com/manvik01/governAI"
ENV NODE_ENV=production \
    PORT=8787 \
    ZENAI4_DB_PATH=/data/zenai4.db
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN mkdir -p /usr/local/bin \
 && ln -s /app/dist/control/admin-cli.js /usr/local/bin/zenai4-admin \
 && ln -s /app/dist/control/admin-cli.js /usr/local/bin/governai-admin \
 && mkdir -p /data /backups \
 && chown -R node:node /data /backups
USER node
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# The gateway drains in-flight requests on SIGTERM before exiting.
STOPSIGNAL SIGTERM
CMD ["node", "dist/gateway/secure-server.js"]
