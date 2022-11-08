# Exists as a test harness for building and running tests in Linux

FROM node:16

COPY ./dist/ /app/dist/
COPY test.ts /app
COPY trusted_setup.txt /app
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
