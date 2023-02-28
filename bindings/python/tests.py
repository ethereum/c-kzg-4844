import glob
from os.path import join
from os.path import isfile

import ckzg

###############################################################################
# Constants
###############################################################################

blob_to_kzg_commitment_tests = "../../tests/blob_to_kzg_commitment/*"
compute_kzg_proof_tests = "../../tests/compute_kzg_proof/*"
compute_blob_kzg_proof_tests = "../../tests/compute_blob_kzg_proof/*"
verify_kzg_proof_tests = "../../tests/verify_kzg_proof/*"
verify_blob_kzg_proof_tests = "../../tests/verify_blob_kzg_proof/*"
verify_blob_kzg_proof_batch_tests = "../../tests/verify_blob_kzg_proof_batch/*"

###############################################################################
# Helper Functions
###############################################################################

def get_blob(path):
    with open(path, "r") as f:
        return bytes.fromhex(f.read())

def get_bytes32(path):
    with open(path, "r") as f:
        return bytes.fromhex(f.read())

def get_bytes48(path):
    with open(path, "r") as f:
        return bytes.fromhex(f.read())

def get_boolean(path):
    with open(path, "r") as f:
        return "true" in f.read()

###############################################################################
# Tests
###############################################################################

def test_blob_to_kzg_commitment(ts):
    for test in glob.glob(blob_to_kzg_commitment_tests):
        blob = get_blob(join(test, "blob.txt"))
        try:
            commitment = ckzg.blob_to_kzg_commitment(blob, ts)
            expected_commitment = get_bytes48(join(test, "commitment.txt"))
            assert commitment == expected_commitment
        except:
            assert not isfile(join(test, "commitment.txt"))

def test_compute_kzg_proof(ts):
    for test in glob.glob(compute_kzg_proof_tests):
        blob = get_blob(join(test, "blob.txt"))
        input_point = get_bytes32(join(test, "input_point.txt"))
        try:
            proof = ckzg.compute_kzg_proof(blob, input_point, ts)
            expected_proof = get_bytes48(join(test, "proof.txt"))
            assert proof == expected_proof
        except:
            assert not isfile(join(test, "proof.txt"))

def test_compute_blob_kzg_proof(ts):
    for test in glob.glob(compute_blob_kzg_proof_tests):
        blob = get_blob(join(test, "blob.txt"))
        try:
            proof = ckzg.compute_blob_kzg_proof(blob, ts)
            expected_proof = get_bytes48(join(test, "proof.txt"))
            assert proof == expected_proof
        except:
            assert not isfile(join(test, "proof.txt"))

def test_verify_kzg_proof(ts):
    for test in glob.glob(verify_kzg_proof_tests):
        commitment = get_bytes48(join(test, "commitment.txt"))
        input_point = get_bytes32(join(test, "input_point.txt"))
        claimed_value = get_bytes32(join(test, "claimed_value.txt"))
        proof = get_bytes48(join(test, "proof.txt"))
        try:
            ckzg.verify_kzg_proof(commitment, input_point, claimed_value, proof, ts)
            assert get_boolean(join(test, "ok.txt"))
        except:
            assert not isfile(join(test, "ok.txt"))

def test_verify_blob_kzg_proof(ts):
    for test in glob.glob(verify_blob_kzg_proof_tests):
        blob = get_bytes32(join(test, "blob.txt"))
        commitment = get_bytes48(join(test, "commitment.txt"))
        proof = get_bytes48(join(test, "proof.txt"))
        try:
            ckzg.verify_blob_kzg_proof(blob, commitment, proof, ts)
            assert get_boolean(join(test, "ok.txt"))
        except:
            assert not isfile(join(test, "ok.txt"))

def test_verify_blob_kzg_proof_batch(ts):
    for test in glob.glob(verify_blob_kzg_proof_batch_tests):
        blob_files = sorted(glob.glob(join(test, "blobs/*")))
        blobs = b"".join([get_blob(b) for b in blob_files])
        commitment_files = sorted(glob.glob(join(test, "commitments/*")))
        commitments = b"".join([get_bytes48(c) for c in commitment_files])
        proof_files = sorted(glob.glob(join(test, "proofs/*")))
        proofs = b"".join([get_bytes48(p) for p in proof_files])

        try:
            ckzg.verify_blob_kzg_proof_batch(blobs, commitments, proofs, ts)
            assert get_boolean(join(test, "ok.txt"))
        except:
            assert not isfile(join(test, "ok.txt"))

###############################################################################
# Main Logic
###############################################################################

if __name__ == "__main__":
    ts = ckzg.load_trusted_setup("../../src/trusted_setup.txt")

    test_blob_to_kzg_commitment(ts)
    test_compute_kzg_proof(ts)
    test_compute_blob_kzg_proof(ts)
    test_verify_kzg_proof(ts)
    test_verify_blob_kzg_proof(ts)
    test_verify_blob_kzg_proof_batch(ts)

    print('tests passed')
