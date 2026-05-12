w
FROM node:20-alpine

# Install git and build tools (required for native modules and GitHub dependencies)
RUN apk add --no-cache git python3 make g++

WORKDIR /app

COPY package*.json ./

# Install dependencies (omit dev, but lockfile optional)
RUN npm install --only=production

COPY . .

# Create required directories
RUN mkdir -p data uploads auth_info_baileys qr_sessions

EXPOSE 3000

CMD ["node", "server.js"]
