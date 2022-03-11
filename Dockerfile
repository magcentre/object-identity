FROM node:slim

WORKDIR /app

COPY package.json .

RUN npm set registry 'http://185.213.175.212:4873/'

RUN npm install

COPY . .

ENV \
  NODE_ENV='development' \
  PORT=5004 \
  URL='mongodb://object-identity-db:27017/magcentre' \
  JWT_SECRET='5avo57Ive6RawrejEspow0prO6risl' \
  JWT_ACCESS_EXPIRATION_MINUTES=120 \
  JWT_REFRESH_EXPIRATION_DAYS=30 \
  JWT_RESET_PASSWORD_EXPIRATION_MINUTES=10 \
  JWT_VERIFY_EMAIL_EXPIRATION_MINUTES=10 \
  OTP_EXPIRY_TIME_MINUTES=10 \
  API_GATEWAY='http://api-gateway-service:5000'

EXPOSE 5004

CMD [ "node", "src/index.js" ]
