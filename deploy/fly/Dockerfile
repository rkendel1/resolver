FROM node:22-slim
RUN npm install -g @appport/resolver@0.4.0 && npm cache clean --force
ENV RESOLVER_ENV=production RESOLVER_LOG_LEVEL=info
USER node
EXPOSE 8080
# State, keys-in-env and the vault live on the Fly volume at /data (one machine: a volume belongs to one machine).
CMD ["resolver", "serve", "--dir", "/data/.resolver", "--port", "8080", "--host", "0.0.0.0"]
