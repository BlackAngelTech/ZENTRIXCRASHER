# Use official Node.js 18 Alpine image (lightweight)
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy only package.json first (better caching)
COPY package.json ./

# Install dependencies without needing package-lock.json
RUN npm install --only=production

# Copy the rest of the application code
COPY . .

# Create directories for data persistence
RUN mkdir -p data uploads zentrixsessions

# Expose the port the app runs on
EXPOSE 3000

# Start the server
CMD ["node", "server.js"]
