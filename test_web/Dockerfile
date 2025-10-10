# Base image
FROM node:18

# Working directory
WORKDIR /app

# Copy package files and install
COPY package*.json ./
RUN npm install

# Copy all source files
COPY . .

# Expose port
EXPOSE 3000

# Run the app
CMD ["npm", "start"]
