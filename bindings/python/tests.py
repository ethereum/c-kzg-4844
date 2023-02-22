import glob
import json

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
# Tests
###############################################################################

def test_blob_to_kzg_commitment(ts):
    for test_file in glob.glob(blob_to_kzg_commitment_tests):
        with open(test_file, "r") as f:
            test = json.load(f)

        blob = bytes.fromhex(test["input"]["blob"])

        try:
            commitment = ckzg.blob_to_kzg_commitment(blob, ts)
            expected_commitment = bytes.fromhex(test["output"]["commitment"])
            assert commitment == expected_commitment
        except:
            assert test["output"]["commitment"] is None


def test_compute_kzg_proof(ts):
    for test_file in glob.glob(compute_kzg_proof_tests):
        with open(test_file, "r") as f:
            test = json.load(f)

        blob = bytes.fromhex(test["input"]["blob"])
        input_point = bytes.fromhex(test["input"]["input_point"])

        try:
            proof = ckzg.compute_kzg_proof(blob, input_point, ts)
            expected_proof = bytes.fromhex(test["output"]["proof"])
            assert proof == expected_proof
        except:
            assert test["output"]["proof"] is None


def test_compute_blob_kzg_proof(ts):
    for test_file in glob.glob(compute_blob_kzg_proof_tests):
        with open(test_file, "r") as f:
            test = json.load(f)

        blob = bytes.fromhex(test["input"]["blob"])

        try:
            proof = ckzg.compute_blob_kzg_proof(blob, ts)
            expected_proof = bytes.fromhex(test["output"]["proof"])
            assert proof == expected_proof
        except:
            assert test["output"]["proof"] is None


def test_verify_kzg_proof(ts):
    for test_file in glob.glob(verify_kzg_proof_tests):
        with open(test_file, "r") as f:
            test = json.load(f)

        commitment = bytes.fromhex(test["input"]["commitment"])
        input_point = bytes.fromhex(test["input"]["input_point"])
        claimed_value = bytes.fromhex(test["input"]["claimed_value"])
        proof = bytes.fromhex(test["input"]["proof"])

        try:
            valid = ckzg.verify_kzg_proof(commitment, input_point, claimed_value, proof, ts)
            expected_valid = test["output"]["valid"]
            assert valid == expected_valid
        except:
            assert test["output"]["valid"] is None


def test_verify_blob_kzg_proof(ts):
    for test_file in glob.glob(verify_blob_kzg_proof_tests):
        with open(test_file, "r") as f:
            test = json.load(f)

        blob = bytes.fromhex(test["input"]["blob"])
        commitment = bytes.fromhex(test["input"]["commitment"])
        proof = bytes.fromhex(test["input"]["proof"])

        try:
            valid = ckzg.verify_blob_kzg_proof(blob, commitment, proof, ts)
            expected_valid = test["output"]["valid"]
            assert valid == expected_valid
        except:
            assert test["output"]["valid"] is None


def test_verify_blob_kzg_proof_batch(ts):
    for test_file in glob.glob(verify_blob_kzg_proof_batch_tests):
        with open(test_file, "r") as f:
            test = json.load(f)

        blobs = b"".join(map(bytes.fromhex, test["input"]["blobs"]))
        commitments = b"".join(map(bytes.fromhex, test["input"]["commitments"]))
        proofs = b"".join(map(bytes.fromhex, test["input"]["proofs"]))

        try:
            valid = ckzg.verify_blob_kzg_proof_batch(blobs, commitments, proofs, ts)
            expected_valid = test["output"]["valid"]
            assert valid == expected_valid
        except:
            assert test["output"]["valid"] is None


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
