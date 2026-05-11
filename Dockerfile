FROM node:18

WORKDIR /app

COPY package.json ./

RUN npm install --omit=dev

COPY . .

RUN mkdir -p data uploads zentrixsessions

EXPOSE 3000

CMD ["node", "server.js"]
