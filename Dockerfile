# Server image: api, ingest, worker and migrate share it (design §12).
FROM node:24.11.1-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/server/package.json packages/server/
COPY packages/edge/package.json packages/edge/
RUN npm ci --omit=dev --workspace @dak/server --include-workspace-root=false && npm cache clean --force
COPY packages/core packages/core
COPY packages/server packages/server
USER node
ENV NODE_ENV=production
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:'+process.env.HTTP_PORT+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "packages/server/src/bin/api.ts"]
