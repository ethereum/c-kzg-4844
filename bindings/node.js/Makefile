clean:
	yarn node-gyp clean
	rm -rf build
	rm -f *.node
	rm -f dist/kzg.node
	rm -f *.a
	rm -f *.o

build: kzg.cxx kzg.ts package.json binding.gyp Makefile
	cd ../../src; make lib
	yarn node-gyp rebuild

test: build
	yarn jest

format:
	yarn prettier --write .

bundle:
	yarn rollup --config rollup.config.js --bundleConfigAsCjs
