# Dockerfile — intentionally insecure to trigger Trivy findings

# ISSUE 1 — pinned to an outdated base image with known CVEs
FROM node:14.17.0

# ISSUE 2 — running as root (no USER instruction)
# Trivy and best-practice checks will flag this

WORKDIR /app

# ISSUE 3 — copying everything including .env, secrets, node_modules
# Should use .dockerignore to exclude sensitive files
COPY . .

# ISSUE 4 — npm install instead of npm ci, and installing devDependencies in prod
RUN npm install

# ISSUE 5 — hardcoded env variable with a secret value
ENV DB_PASSWORD="SuperSecret123!"
ENV NODE_ENV="production"

# ISSUE 6 — exposing port 3000 is fine, but no HEALTHCHECK defined
EXPOSE 3000

# ISSUE 7 — no non-root user; process runs as root inside container
CMD ["node", "app.js"]
