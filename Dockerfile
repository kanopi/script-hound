# ScriptHound image: sniffs out malicious front-end code.
#
# Keep this tag in step with the "playwright" version in package.json and the
# image in .circleci/config.yml. The base image already contains the matching
# Chromium build, so no `playwright install` step is needed.
FROM mcr.microsoft.com/playwright:v1.63.0-noble

ARG VERSION=dev
LABEL org.opencontainers.image.title="ScriptHound" \
      org.opencontainers.image.description="Sniffs out malicious front-end code: passive front-end security scanner in a headless browser" \
      org.opencontainers.image.vendor="Kanopi Studios" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.url="https://hub.docker.com/r/kanopi/script-hound" \
      org.opencontainers.image.source="https://github.com/kanopi/script-hound" \
      org.opencontainers.image.documentation="https://github.com/kanopi/script-hound#readme"

ENV NODE_ENV=production

# jq, for the report.json recipes in docs/jq-recipes.md:
#   docker run --rm -v "$PWD":/data --entrypoint jq kanopi/script-hound -r '<recipe>' reports/report.json
RUN apt-get update && apt-get install -y --no-install-recommends jq && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json LICENSE NOTICE ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY scan.mjs ./
COPY lib ./lib
# Vulnerable-library database (Retire.js, Apache-2.0); see data/README.md
COPY data ./data
# Brand SVGs for the HTML report (logo, favicon); see brand/README.md
COPY brand/*.svg ./brand/
# The source files may be owner-only (600) and the scanner runs as the non-root pwuser: make them readable.
RUN chmod 755 /app/brand && chmod 644 /app/brand/*.svg

# Relative paths (sites.json, baseline.json, reports/) resolve against /data,
# so mount your working directory there:
#   docker run --rm --ipc=host -v "$PWD":/data kanopi/script-hound --urls https://example.com/
RUN mkdir -p /data && chown pwuser:pwuser /data
WORKDIR /data
USER pwuser

ENTRYPOINT ["node", "/app/scan.mjs"]
