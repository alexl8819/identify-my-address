FROM node:lts-alpine
# Create app directory
WORKDIR /usr/src/app
RUN apk add --no-cache git
# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 9000
CMD ["npm", "start"]