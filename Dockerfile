FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY . .
ENV PORT=8080 AGENT_PATH=/agent NODE_ENV=production
EXPOSE 8080
CMD ["node", "src/server.mjs"]
