all: clean build format test bundle

clean:
	yarn node-gyp clean
	rm -rf build
	rm -rf dist
	rm -f *.node
	rm -f *.a
	rm -f *.o

build: src/kzg.cxx lib/kzg.ts package.json binding.gyp Makefile
	cd ../../src && make c_kzg_4844.o && cp c_kzg_4844.o ../bindings/node.js
	yarn install
	yarn node-gyp rebuild

test: build
	yarn jest

format:
	yarn prettier --write .

bundle: clean
	mkdir dist
	cp README.md dist/README.md
	cp package.json dist/package.json
	cp binding.dist.gyp dist/binding.gyp
	node_modules/.bin/tsc -p tsconfig.build.json
	cp -r src dist/src
	mkdir -p dist/deps/c-kzg
	cp -r ../../blst dist/deps
	cp ../../src/c_kzg_4844.c dist/deps/c-kzg
	cp ../../src/c_kzg_4844.h dist/deps/c-kzg

publish: bundle
	cd dist
	npm publish

linux-test: bundle
	docker build -t "linux-test" .
	docker logs --follow `docker run -d linux-test`
