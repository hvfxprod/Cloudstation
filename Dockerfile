# Stage 1: Build frontend
FROM node:22-alpine AS frontend
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Runtime (frontend static + server)
FROM node:22-alpine
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=9000
ENV DATA_PATH=/data

# Server only
COPY server/package.json server/
RUN cd server && npm install --omit=dev

COPY server/ server/
COPY --from=frontend /app/dist dist/

EXPOSE 9000

CMD ["node", "server/index.js"]
