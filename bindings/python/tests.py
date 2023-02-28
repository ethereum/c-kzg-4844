import glob
import yaml

import ckzg

###############################################################################
# Constants
###############################################################################

blob_to_kzg_commitment_tests = "../../tests/blob_to_kzg_commitment/*/*/*"
compute_kzg_proof_tests = "../../tests/compute_kzg_proof/*/*/*"
compute_blob_kzg_proof_tests = "../../tests/compute_blob_kzg_proof/*/*/*"
verify_kzg_proof_tests = "../../tests/verify_kzg_proof/*/*/*"
verify_blob_kzg_proof_tests = "../../tests/verify_blob_kzg_proof/*/*/*"
verify_blob_kzg_proof_batch_tests = "../../tests/verify_blob_kzg_proof_batch/*/*/*"

###############################################################################
# Helper Functions
###############################################################################

def bytes_from_hex(hexstring):
    return bytes.fromhex(hexstring.replace("0x", ""))

###############################################################################
# Tests
###############################################################################

def test_blob_to_kzg_commitment(ts):
    for test_file in glob.glob(blob_to_kzg_commitment_tests):
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blob = bytes_from_hex(test["input"]["blob"])

        try:
            commitment = ckzg.blob_to_kzg_commitment(blob, ts)
            expected_commitment = bytes_from_hex(test["output"])
            assert commitment == expected_commitment, f"{test_file}\n{commitment.hex()=}\n{expected_commitment.hex()=}"
        except:
            assert test["output"] is None


def test_compute_kzg_proof(ts):
    for test_file in glob.glob(compute_kzg_proof_tests):
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blob = bytes_from_hex(test["input"]["blob"])
        input_point = bytes_from_hex(test["input"]["z"])

        try:
            proof = ckzg.compute_kzg_proof(blob, input_point, ts)
            expected_proof = bytes_from_hex(test["output"])
            assert proof == expected_proof, f"{test_file}\n{proof.hex()=}\n{expected_proof.hex()=}"
        except:
            assert test["output"] is None


def test_compute_blob_kzg_proof(ts):
    for test_file in glob.glob(compute_blob_kzg_proof_tests):
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blob = bytes_from_hex(test["input"]["blob"])

        try:
            proof = ckzg.compute_blob_kzg_proof(blob, ts)
            expected_proof = bytes_from_hex(test["output"])
            assert proof == expected_proof, f"{test_file}\n{proof.hex()=}\n{expected_proof.hex()=}"
        except:
            assert test["output"] is None


def test_verify_kzg_proof(ts):
    for test_file in glob.glob(verify_kzg_proof_tests):
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        commitment = bytes_from_hex(test["input"]["commitment"])
        input_point = bytes_from_hex(test["input"]["z"])
        claimed_value = bytes_from_hex(test["input"]["y"])
        proof = bytes_from_hex(test["input"]["proof"])

        try:
            valid = ckzg.verify_kzg_proof(commitment, input_point, claimed_value, proof, ts)
            expected_valid = test["output"]
            assert valid == expected_valid, f"{test_file}\n{valid=}\n{expected_valid=}"
        except:
            assert test["output"] is None


def test_verify_blob_kzg_proof(ts):
    for test_file in glob.glob(verify_blob_kzg_proof_tests):
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blob = bytes_from_hex(test["input"]["blob"])
        commitment = bytes_from_hex(test["input"]["commitment"])
        proof = bytes_from_hex(test["input"]["proof"])

        try:
            valid = ckzg.verify_blob_kzg_proof(blob, commitment, proof, ts)
            expected_valid = test["output"]
            assert valid == expected_valid, f"{test_file}\n{valid=}\n{expected_valid=}"
        except:
            assert test["output"] is None


def test_verify_blob_kzg_proof_batch(ts):
    for test_file in glob.glob(verify_blob_kzg_proof_batch_tests):
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blobs = b"".join(map(bytes_from_hex, test["input"]["blobs"]))
        commitments = b"".join(map(bytes_from_hex, test["input"]["commitments"]))
        proofs = b"".join(map(bytes_from_hex, test["input"]["proofs"]))

        try:
            valid = ckzg.verify_blob_kzg_proof_batch(blobs, commitments, proofs, ts)
            expected_valid = test["output"]
            assert valid == expected_valid, f"{test_file}\n{valid=}\n{expected_valid=}"
        except:
            assert test["output"] is None


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
