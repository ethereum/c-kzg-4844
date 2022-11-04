'use strict';

/**
 * The public interface of this module exposes the functions as specified by
 * https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#kzg
 */
const kzg = require("./kzg.node");
const FIELD_ELEMENTS_PER_BLOB = kzg.FIELD_ELEMENTS_PER_BLOB;
const BYTES_PER_FIELD = kzg.BYTES_PER_FIELD;
// Stored as internal state
let setupHandle;
function loadTrustedSetup(filePath) {
    if (setupHandle) {
        throw new Error("Call freeTrustedSetup before loading a new trusted setup.");
    }
    setupHandle = kzg.loadTrustedSetup(filePath);
}
function freeTrustedSetup() {
    if (!setupHandle) {
        throw new Error("You must call loadTrustedSetup before freeTrustedSetup.");
    }
    kzg.freeTrustedSetup(setupHandle);
    setupHandle = undefined;
}
function blobToKzgCommitment(blob) {
    if (!setupHandle) {
        throw new Error("You must call loadTrustedSetup to initialize KZG.");
    }
    return kzg.blobToKzgCommitment(blob, setupHandle);
}
function computeAggregateKzgProof(blobs) {
    if (!setupHandle) {
        throw new Error("You must call loadTrustedSetup to initialize KZG.");
    }
    return kzg.computeAggregateKzgProof(blobs, setupHandle);
}
function verifyAggregateKzgProof(blobs, expectedKzgCommitments, kzgAggregatedProof) {
    if (!setupHandle) {
        throw new Error("You must call loadTrustedSetup to initialize KZG.");
    }
    return kzg.verifyAggregateKzgProof(blobs, expectedKzgCommitments, kzgAggregatedProof, setupHandle);
}

exports.BYTES_PER_FIELD = BYTES_PER_FIELD;
exports.FIELD_ELEMENTS_PER_BLOB = FIELD_ELEMENTS_PER_BLOB;
exports.blobToKzgCommitment = blobToKzgCommitment;
exports.computeAggregateKzgProof = computeAggregateKzgProof;
exports.freeTrustedSetup = freeTrustedSetup;
exports.loadTrustedSetup = loadTrustedSetup;
exports.verifyAggregateKzgProof = verifyAggregateKzgProof;
