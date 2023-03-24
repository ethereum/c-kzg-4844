FROM node:16-alpine
RUN apk update && apk add --no-cache g++ make python3

WORKDIR /app/bindings/node.js

COPY dist .
COPY test ./test
COPY jest.config.js .
COPY yaml-tests ../../tests

RUN yarn install
CMD ["yarn", "jest"]
