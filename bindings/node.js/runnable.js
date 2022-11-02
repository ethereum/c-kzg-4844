'use strict';

const kzg = require('ckzg');
console.log('Loaded KZG library with functions:');
console.log(kzg);

console.log('Sanity checking C interop by calling no-op function...');
console.log('PASS', kzg.testFunction());

// KZGSettings* loadTrustSetup(const char* file);
console.log('Invoking load_trusted_setup...');
const kzgSettings = kzg.loadTrustedSetup('../../src/trusted_setup.txt');
console.log('PASS');
console.log(
  'load_trusted_setup yielded KZGSettings: ',
  { ...kzgSettings },
  kzgSettings.fs,
);

for (var key in kzgSettings) {
  console.log(key);
}
console.log(kzgSettings.getCPtr());

// void freeTrustedSetup(KZGSettings *s);
let config = {};
console.log('Invoking free_trusted_setup...');
const freeResult = kzg.freeTrustedSetup(kzgSettings);
console.log('PASS', freeResult);
