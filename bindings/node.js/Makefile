# For a less verbose yarn
YARN = yarn --silent

.PHONY: all
all: format build test

# Cleans native dependency, bindings and typescript artifacts
.PHONY: clean
clean:
	@rm -rf build
	@rm -rf dist
	@rm -rf deps
	@rm -f *.node
	@rm -f *.a
	@rm -f *.o
	@rm -rf ref-tests

# Cleans typescript dependencies
.PHONY: clean-install
clean-install:
	@rm -rf node_modules

# Installs typescript dependencies
.PHONY: install
install:
	@$(YARN) install --ignore-scripts

# Cleans and rebuilds native dependencies, bindings and typescript wrapper
.PHONY: build
build: install clean
	@# Prepare the dependencies directory
	@mkdir -p deps/c-kzg
	@cp -r ../../blst deps
	@# Copy files
	@cp ../../src/ckzg.c deps/c-kzg
	@cp ../../src/ckzg.h deps/c-kzg
	@cp -r ../../src/common deps/c-kzg
	@cp -r ../../src/eip4844 deps/c-kzg
	@cp -r ../../src/eip7594 deps/c-kzg
	@cp -r ../../src/setup deps/c-kzg
	@# Copy trusted setup
	@cp ../../src/trusted_setup.txt deps/c-kzg
	@# Build the bindings
	@$(YARN) node-gyp --loglevel=warn configure
	@$(YARN) node-gyp --loglevel=warn build

# Run unit tests and ref-tests
.PHONY: test
test: install
	@echo
	@$(YARN) jest

# Lint js/ts code
.PHONY: format
format: install
	@$(YARN) eslint --fix --quiet --color --ext .ts lib/ test/
	@clang-format -i src/kzg.cxx

# Publish package to npm (requires an auth token)
.PHONY: publish
publish: build test
	@npm publish

# Run ref-tests in linux environment for cross-compatibility check
.PHONY: linux-test
linux-test: build
	@# Docker cannot copy from outside this dir
	@cp -r ../../tests ref-tests
	@docker build -t "linux-test" .
	@docker logs --follow `docker run -d linux-test`
	@rm -rf ref-tests
