# syntax=docker/dockerfile:1

# ---- build: type-check and bundle the React front end ----------------------------------------
FROM node:25-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src
RUN npm run build

# ---- runtime: Nginx as an unprivileged user (SC-12) ------------------------------------------
FROM nginxinc/nginx-unprivileged:1.28-alpine
COPY nginx/securedesk.conf /etc/nginx/conf.d/default.conf
COPY nginx/security-headers.conf nginx/api-proxy.conf /etc/nginx/snippets/
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8443
