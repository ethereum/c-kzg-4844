'use strict';

console.log('testing...');

const kzg = require('ckzg');

console.log(kzg);

console.log('Invoking function...', kzg.testFunction());

console.log('Invoking freeTrustedSetup...', kzg.freeTrustedSetup(null));
