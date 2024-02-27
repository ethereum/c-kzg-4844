# Contribution Guidelines

Thanks for your interest in contributing to the Node.js bindings for
c-kzg-4844.

## Prerequisites

- [NodeJS](https://nodejs.org/) (LTS)
- [Yarn](https://yarnpkg.com/)

## Setup

Open a terminal and navigate to the root of the `c-kzg-4844` repo and run the
following commands if you have not already done so:

```sh
git submodule update --init # Install the blst submodule
cd src
make blst # Build blst
cd ../bindings/node.js
yarn install --ignore-scripts # Install dependencies
make # Build bindings and verify build worked
```

## Project Commands

- `make clean` - cleans artifacts
- `make build` - prepares assets and builds bindings
- `make test` - runs unit tests
- `make format` - lints code
- `make bundle` - builds `dist` for publishing
- `make publish` - runs `npm publish`

## `n-api` and `node-addon-api`

There are two different flavors of abi-stable node addons.
[n-api](https://nodejs.org/api/n-api.html) is the `C` api that is natively
exported by `node.js`. There is also a header-only `C++` implementation of the
`n-api` called [node-addon-api](https://github.com/nodejs/node-addon-api).
There is mixed usage of the two in this library.

The addon was built to be
[context-aware](https://nodejs.github.io/node-addon-examples/special-topics/context-awareness/),
so it will be safe to run on a worker thread. Be sure not to use any
static/global variables as those are not thread safe.
