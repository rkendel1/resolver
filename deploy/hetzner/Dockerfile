FROM node:22-slim
# The published @appport/resolver this repository is at (packages/server/package.json), passed by deploy:hetzner.
ARG RESOLVER_VERSION=0.4.1
RUN npm install -g @appport/resolver@${RESOLVER_VERSION} && npm cache clean --force
ENV RESOLVER_ENV=production RESOLVER_LOG_LEVEL=info
USER node
EXPOSE 8080
CMD ["node", "/usr/local/lib/node_modules/@appport/resolver/dist/cli.js", "serve", "--dir", "/data/.resolver", "--port", "8080", "--host", "0.0.0.0"]
