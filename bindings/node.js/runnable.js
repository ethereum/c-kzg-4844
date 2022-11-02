'use strict';

console.log('testing...');

const kzg = require('ckzg');

console.log(kzg);

console.log('Invoking function...', kzg.testFunction());

let config = {};
console.log('Invoking freeTrustedSetup...', kzg.freeTrustedSetup(config));
