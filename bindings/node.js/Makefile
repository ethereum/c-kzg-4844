all: clean build format test

clean:
	rm -rf build
	rm -rf dist
	rm -rf deps
	rm -f *.node
	rm -f *.a
	rm -f *.o
	rm -rf node_modules
	rm -rf yaml-tests

build: clean src/kzg.cxx lib/kzg.ts package.json binding.gyp Makefile
	mkdir -p deps/c-kzg
	cp -r ../../blst deps
	cp ../../src/c_kzg_4844.c deps/c-kzg
	cp ../../src/c_kzg_4844.h deps/c-kzg
	# Patch the blst_aux.h to fix a compiler error
	awk '{gsub(/typedef struct \{\} blst_uniq;/, "typedef struct { int dummy; } blst_uniq;")}1' deps/blst/bindings/blst_aux.h > blst_aux_temp.h && mv blst_aux_temp.h deps/blst/bindings/blst_aux.h
	yarn install
	yarn node-gyp rebuild
	yarn tsc -p tsconfig.build.json
	# Build the distribution
	cp -r src dist/src
	cp README.md dist/README.md
	cp package.json dist/package.json
	cp binding.gyp dist/binding.gyp
	mv deps dist

test: build
	yarn jest

format:
	yarn prettier --write .

publish: build
	cd dist
	npm publish

linux-test: build
	cp -r ../../tests yaml-tests
	docker build -t "linux-test" .
	docker logs --follow `docker run -d linux-test`
	rm -rf yaml-tests
