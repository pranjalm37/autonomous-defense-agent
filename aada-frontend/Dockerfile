# ── Stage 1: Build ────────────────────────────────────
# Compile the React/TS app to static assets with Vite.
FROM node:20-alpine AS build
WORKDIR /app

# Install deps from the lockfile first for layer caching.
COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY . .
# VITE_API_BASE is baked at build time; default "/api/v1" (nginx proxies it).
ARG VITE_API_BASE=/api/v1
ENV VITE_API_BASE=$VITE_API_BASE
RUN npm run build

# ── Stage 2: Serve ────────────────────────────────────
# Ship only the static bundle behind nginx — tiny, no Node runtime.
FROM nginx:1.27-alpine AS runtime
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=5 \
  CMD wget -qO- http://localhost:80/ >/dev/null 2>&1 || exit 1

CMD ["nginx", "-g", "daemon off;"]
