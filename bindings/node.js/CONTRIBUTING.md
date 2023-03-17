# Contribution Guidelines

Thanks for your interest in contributing to the Node.js bindings for c-kzg. It's people like you that push the Ethereum ecosystem forward!!

## Prerequisites

- [NodeJS](https://nodejs.org/) (LTS)
- [Yarn](https://yarnpkg.com/)

## Setup

Open a terminal and navigate to the root of the `c-kzg-4844` repo and run the following commands if you have not already done so:

```sh
git submodule update --init # Install the blst submodule
cd src
make blst # Build blst
cd ../bindings/node.js
yarn install --ignore-scripts # Install dependencies
make # Build bindings and verify build worked
```

## Project Commands

`make clean` - cleans artifacts

`make build` - prepares assets and builds bindings

`make test` - runs unit tests

`make format` - lints code

`make bundle` - builds `dist` for publishing

`make publish` - runs `npm publish`
