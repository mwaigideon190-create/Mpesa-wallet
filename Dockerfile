FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production

# better-sqlite3 normally installs a prebuilt binary; these tools are only the fallback if it must compile.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
