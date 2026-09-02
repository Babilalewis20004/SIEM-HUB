FROM node:24-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Binding port 80 needs root, so the standard nginx image runs its master
# process as root (workers drop to the 'nginx' user, master doesn't). The
# nginx-unprivileged image is the same nginx build listening on 8080 instead,
# so it can run as non-root end-to-end -- no root process in the container.
FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

USER nginx
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/ || exit 1
