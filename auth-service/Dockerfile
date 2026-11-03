FROM node:20-alpine
WORKDIR /app

# Install dependencies first so this layer is cached when only source changes
COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src
USER node
EXPOSE 4001
CMD ["node", "src/index.js"]
