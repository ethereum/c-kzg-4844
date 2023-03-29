# For a less verbose yarn.
YARN = yarn --silent

.PHONY: all
all: format build test bundle

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
	@cp ../../src/c_kzg_4844.c deps/c-kzg
	@cp ../../src/c_kzg_4844.h deps/c-kzg
	@# Patch the blst_aux.h to fix a compiler error
	@awk '{gsub(/typedef struct \{\} blst_uniq;/, "typedef struct { int dummy; } blst_uniq;")}1' \
		deps/blst/bindings/blst_aux.h > blst_aux_temp.h
	@mv blst_aux_temp.h deps/blst/bindings/blst_aux.h
	@# Build the bindings
	@$(YARN) node-gyp --loglevel=warn configure
	@$(YARN) node-gyp --loglevel=warn build

# Bundle the distribution, also helpful for cross compatibility checks
.PHONY: bundle
bundle: build
	@mkdir dist
	@mv deps dist
	@cp -r lib dist/lib
	@cp -r src dist/src
	@cp README.md dist/README.md
	@cp package.json dist/package.json
	@cp binding.gyp dist/binding.gyp

# Run unit tests and ref-tests
.PHONY: test
test: install
	@echo
	@$(YARN) jest

# Lint js/ts code
.PHONY: format
format: install
	@$(YARN) prettier --loglevel=warn --write .

# Publish package to npm (requires an auth token)
.PHONY: publish
publish: build
	@cd dist
	@npm publish

# Run ref-tests in linux environment for cross-compatability check
.PHONY: linux-test
linux-test: build
	# Docker cannot copy from outside this dir
	@cp -r ../../tests ref-tests
	@docker build -t "linux-test" .
	@docker logs --follow `docker run -d linux-test`
	@rm -rf ref-tests
