# CRA risk assessment – single container, no build step.
# Pin the base image by digest in your registry mirror for reproducible builds.
FROM docker.io/library/node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM docker.io/library/node:24-alpine
LABEL org.opencontainers.image.title="cra-risk-assessment" \
      org.opencontainers.image.description="CRA Self Assessment Helper: risk assessment, SBOM / vulnerability tracking and technical documentation per EU Cyber Resilience Act"
ENV NODE_ENV=production \
    PORT=8080 \
    DATABASE_URL=sqlite:/data/cra.db \
    AUTH_MODE=local
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY public ./public
COPY examples ./examples
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.js"]
