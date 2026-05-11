# Use official Node.js 18 Alpine image (smaller size)
FROM node:18-alpine

# Set working directory inside container
WORKDIR /app

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy the rest of the application code
COPY . .

# Create directories for data persistence (if not exist)
RUN mkdir -p data uploads zentrixsessions

# Expose the port the app runs on
EXPOSE 3000

# Command to run the server
CMD ["node", "server.js"]
