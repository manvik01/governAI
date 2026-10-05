# governAI secure gateway - stateless container, state lives in the database volume.
#
#   docker build -t governai-gateway .
#   docker run -p 8787:8787 -v governai-data:/data governai-gateway
#
# Scale-out note: SQLite is single-node. To run several replicas behind a load
# balancer, point GOVERNAI_DB_PATH at shared storage only for a single writer,
# or (the intended path) move the stores to Postgres - see docs/PRD.md section 7.

FROM node:22-bookworm AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    PORT=8787 \
    GOVERNAI_DB_PATH=/data/governai.db
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN mkdir -p /data && chown -R node:node /data /app
USER node
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# SIGTERM is handled for graceful drain, so autoscalers can remove replicas safely.
CMD ["node", "dist/gateway/secure-server.js"]
