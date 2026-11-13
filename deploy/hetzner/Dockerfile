FROM node:22-slim
RUN npm install -g @appport/resolver@0.4.0 && npm cache clean --force
ENV RESOLVER_ENV=production RESOLVER_LOG_LEVEL=info
USER node
EXPOSE 8080
CMD ["node", "/usr/local/lib/node_modules/@appport/resolver/dist/cli.js", "serve", "--dir", "/data/.resolver", "--port", "8080", "--host", "0.0.0.0"]
