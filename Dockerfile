FROM node:24-alpine

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080
ENV DATABASE_PATH=/data/directory.db

COPY package.json ./
COPY src ./src
COPY public ./public
COPY scripts ./scripts

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8080

CMD ["node", "src/server.js"]
