'use strict';

/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const kzg = require("./kzg.node");
const FIELD_ELEMENTS_PER_BLOB = kzg.FIELD_ELEMENTS_PER_BLOB;
const BYTES_PER_FIELD_ELEMENT = kzg.BYTES_PER_FIELD_ELEMENT;
// Stored as internal state
let setupHandle;
function requireSetupHandle() {
    if (!setupHandle) {
        throw new Error("You must call loadTrustedSetup to initialize KZG.");
    }
    return setupHandle;
}
function loadTrustedSetup(filePath) {
    if (setupHandle) {
        throw new Error("Call freeTrustedSetup before loading a new trusted setup.");
    }
    setupHandle = kzg.loadTrustedSetup(filePath);
}
function freeTrustedSetup() {
    kzg.freeTrustedSetup(requireSetupHandle());
    setupHandle = undefined;
}
function blobToKzgCommitment(blob) {
    return kzg.blobToKzgCommitment(blob, requireSetupHandle());
}
function computeAggregateKzgProof(blobs) {
    return kzg.computeAggregateKzgProof(blobs, requireSetupHandle());
}
function verifyAggregateKzgProof(blobs, expectedKzgCommitments, kzgAggregatedProof) {
    return kzg.verifyAggregateKzgProof(blobs, expectedKzgCommitments, kzgAggregatedProof, requireSetupHandle());
}

exports.BYTES_PER_FIELD_ELEMENT = BYTES_PER_FIELD_ELEMENT;
exports.FIELD_ELEMENTS_PER_BLOB = FIELD_ELEMENTS_PER_BLOB;
exports.blobToKzgCommitment = blobToKzgCommitment;
exports.computeAggregateKzgProof = computeAggregateKzgProof;
exports.freeTrustedSetup = freeTrustedSetup;
exports.loadTrustedSetup = loadTrustedSetup;
exports.verifyAggregateKzgProof = verifyAggregateKzgProof;
