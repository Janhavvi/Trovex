FROM node:22-alpine
WORKDIR /app
COPY server.js ./server.js
ENV PORT=10000
EXPOSE 10000
USER node
CMD ["node", "server.js"]