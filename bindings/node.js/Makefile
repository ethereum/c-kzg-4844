all: clean build format test bundle

clean:
	yarn node-gyp clean
	rm -rf build
	rm -rf dist
	rm -f *.node
	rm -f *.a
	rm -f *.o

build: kzg.cxx kzg.ts package.json binding.gyp Makefile
	cd ../../src; make lib
	yarn install
	yarn node-gyp rebuild

test: build
	yarn jest

format:
	yarn prettier --write .

bundle: clean
	yarn rollup --config rollup.config.js --bundleConfigAsCjs
	mkdir -p dist/deps/c-kzg
	cp -r ../../blst dist/deps
	cp ../../src/c_kzg_4844.c dist/deps/c-kzg
	cp ../../src/c_kzg_4844.h dist/deps/c-kzg

publish: bundle
	mv binding.gyp binding.gyp.bak
	cp binding.dist.gyp binding.gyp
	npm publish && mv binding.gyp.bak binding.gyp || mv binding.gyp.bak binding.gyp


linux-test: bundle
	docker build -t "linux-test" .
	docker logs --follow `docker run -d linux-test`
