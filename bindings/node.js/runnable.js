'use strict';

var bindings = require('bindings');
console.log('Bindings', bindings);

const kzg = bindings('kzg.node');
console.log('Loaded KZG library with functions:');
console.log(kzg);

// console.log('Sanity checking C interop by calling no-op function...');
// console.log('PASS', kzg.testFunction());

// KZGSettings* loadTrustSetup(const char* file);
console.log('Invoking load_trusted_setup...');
const kzgSettingsHandle = kzg.loadTrustedSetup('../../src/trusted_setup.txt');
console.log('PASS');
console.log(
  'load_trusted_setup yielded KZGSettings with handle: ',
  kzgSettingsHandle,
);

// void freeTrustedSetup(KZGSettings *s);
console.log('Invoking free_trusted_setup...');
const freeResult = kzg.freeTrustedSetup(kzgSettingsHandle);
console.log('PASS', freeResult);
