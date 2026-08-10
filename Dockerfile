FROM node

WORKDIR /app
COPY ./server /app/
RUN npm ci

CMD ["npm", "start"]