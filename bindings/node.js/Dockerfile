# Exists as a test harness for building and running tests in Linux


FROM node:16-alpine
RUN apk update && apk add --no-cache g++ make python3


COPY ./dist/ /app/dist/
COPY test.ts /app
COPY testing_trusted_setups.json /app
COPY kzg.ts /app
COPY kzg.cxx /app
COPY package.json /app
COPY tsconfig.json /app
COPY babel.config.js /app
COPY jest.config.js /app
COPY binding.dist.gyp /app/binding.gyp

WORKDIR /app

RUN yarn install

CMD ["yarn", "jest"]
