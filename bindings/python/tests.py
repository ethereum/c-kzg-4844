import glob
import yaml

import ckzg

###############################################################################
# Constants
###############################################################################

BLOB_TO_KZG_COMMITMENT_TESTS = "../../tests/blob_to_kzg_commitment/*/*/data.yaml"
COMPUTE_KZG_PROOF_TESTS = "../../tests/compute_kzg_proof/*/*/data.yaml"
COMPUTE_BLOB_KZG_PROOF_TESTS = "../../tests/compute_blob_kzg_proof/*/*/data.yaml"
VERIFY_KZG_PROOF_TESTS = "../../tests/verify_kzg_proof/*/*/data.yaml"
VERIFY_BLOB_KZG_PROOF_TESTS = "../../tests/verify_blob_kzg_proof/*/*/data.yaml"
VERIFY_BLOB_KZG_PROOF_BATCH_TESTS = "../../tests/verify_blob_kzg_proof_batch/*/*/data.yaml"


###############################################################################
# Helper Functions
###############################################################################

def bytes_from_hex(hexstring):
    return bytes.fromhex(hexstring.replace("0x", ""))


###############################################################################
# Tests
###############################################################################

def test_blob_to_kzg_commitment(ts):
    test_files = glob.glob(BLOB_TO_KZG_COMMITMENT_TESTS)
    assert len(test_files) > 0

    for test_file in test_files:
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blob = bytes_from_hex(test["input"]["blob"])

        try:
            commitment = ckzg.blob_to_kzg_commitment(blob, ts)
        except:
            assert test["output"] is None
            continue

        expected_commitment = bytes_from_hex(test["output"])
        assert commitment == expected_commitment, f"{test_file}\n{commitment.hex()=}\n{expected_commitment.hex()=}"


def test_compute_kzg_proof(ts):
    test_files = glob.glob(COMPUTE_KZG_PROOF_TESTS)
    assert len(test_files) > 0

    for test_file in test_files:
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blob = bytes_from_hex(test["input"]["blob"])
        z = bytes_from_hex(test["input"]["z"])

        try:
            proof, y = ckzg.compute_kzg_proof(blob, z, ts)
        except:
            assert test["output"] is None
            continue

        expected_proof = bytes_from_hex(test["output"][0])
        assert proof == expected_proof, f"{test_file}\n{proof.hex()=}\n{expected_proof.hex()=}"

        expected_y = bytes_from_hex(test["output"][1])
        assert y == expected_y, f"{test_file}\n{y.hex()=}\n{expected_y.hex()=}"


def test_compute_blob_kzg_proof(ts):
    test_files = glob.glob(COMPUTE_BLOB_KZG_PROOF_TESTS)
    assert len(test_files) > 0

    for test_file in test_files:
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blob = bytes_from_hex(test["input"]["blob"])
        commitment = bytes_from_hex(test["input"]["commitment"])

        try:
            proof = ckzg.compute_blob_kzg_proof(blob, commitment, ts)
        except:
            assert test["output"] is None
            continue

        expected_proof = bytes_from_hex(test["output"])
        assert proof == expected_proof, f"{test_file}\n{proof.hex()=}\n{expected_proof.hex()=}"


def test_verify_kzg_proof(ts):
    test_files = glob.glob(VERIFY_KZG_PROOF_TESTS)
    assert len(test_files) > 0

    for test_file in test_files:
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        commitment = bytes_from_hex(test["input"]["commitment"])
        z = bytes_from_hex(test["input"]["z"])
        y = bytes_from_hex(test["input"]["y"])
        proof = bytes_from_hex(test["input"]["proof"])

        try:
            valid = ckzg.verify_kzg_proof(commitment, z, y, proof, ts)
        except:
            assert test["output"] is None
            continue

        expected_valid = test["output"]
        assert valid == expected_valid, f"{test_file}\n{valid=}\n{expected_valid=}"


def test_verify_blob_kzg_proof(ts):
    test_files = glob.glob(VERIFY_BLOB_KZG_PROOF_TESTS)
    assert len(test_files) > 0

    for test_file in test_files:
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blob = bytes_from_hex(test["input"]["blob"])
        commitment = bytes_from_hex(test["input"]["commitment"])
        proof = bytes_from_hex(test["input"]["proof"])

        try:
            valid = ckzg.verify_blob_kzg_proof(blob, commitment, proof, ts)
        except:
            assert test["output"] is None
            continue

        expected_valid = test["output"]
        assert valid == expected_valid, f"{test_file}\n{valid=}\n{expected_valid=}"


def test_verify_blob_kzg_proof_batch(ts):
    test_files = glob.glob(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS)
    assert len(test_files) > 0

    for test_file in test_files:
        with open(test_file, "r") as f:
            test = yaml.safe_load(f)

        blobs = b"".join(map(bytes_from_hex, test["input"]["blobs"]))
        commitments = b"".join(map(bytes_from_hex, test["input"]["commitments"]))
        proofs = b"".join(map(bytes_from_hex, test["input"]["proofs"]))

        try:
            valid = ckzg.verify_blob_kzg_proof_batch(blobs, commitments, proofs, ts)
        except:
            assert test["output"] is None
            continue

        expected_valid = test["output"]
        assert valid == expected_valid, f"{test_file}\n{valid=}\n{expected_valid=}"


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

    print("tests passed")
