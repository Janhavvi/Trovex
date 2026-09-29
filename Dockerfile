FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=10000
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server.js ./server.js
COPY server ./server
COPY --from=build /app/dist ./dist
EXPOSE 10000
USER node
CMD ["node", "server.js"]