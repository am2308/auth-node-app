# Use an official Node.js runtime as a parent image
FROM node:16-alpine

# Create app directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install app dependencies
RUN npm ci

# Copy the rest of the application
COPY . .

# Expose the app’s port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]