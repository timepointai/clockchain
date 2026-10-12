# Image for the static explorer (web/explorer): nginx serving the assembled
# dist/ tree. Deployment status is in docs/PUBLIC-ACCESS.md.
#
# Build context is the repo root, so the root deny-by-default .dockerignore
# applies (it re-includes deploy/explorer/ and web/explorer/dist/ for this
# image). Do not add a Dockerfile.dockerignore next to this file: BuildKit
# would use it in place of the root one.
#
# Nothing is compiled inside the image. Assemble dist/ first, from the repo
# root, naming the gateway origin the page reads from:
#
#   web/explorer/build.sh --api-base <gateway-origin>/public/v1
#   docker build -f deploy/explorer/Dockerfile -t <tag> .
#
# dist/ is not committed; an image built without it fails at the COPY.

# Listens on 8080 and runs as the unprivileged nginx user (uid 101). Its
# mime.types already maps .wasm to application/wasm.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY deploy/explorer/nginx.conf /etc/nginx/conf.d/default.conf
USER root
RUN rm -rf /usr/share/nginx/html/*
USER nginx
COPY web/explorer/dist/ /usr/share/nginx/html/
EXPOSE 8080
