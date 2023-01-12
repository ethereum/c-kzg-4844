import ckzg
import random

# Commit to a few random blobs

BLOB_SIZE = 4096
MAX_BLOBS_PER_BLOCK = 16

blobs = [
  # use zero final bytes to easily ensure the encodings are valid
  b''.join([b''.join([random.randbytes(31), bytes(1)]) for _ in range(BLOB_SIZE)])
  for _ in range(3)
]

ts = ckzg.load_trusted_setup("../../src/trusted_setup.txt")

kzg_commitments = b''.join([ckzg.blob_to_kzg_commitment(blob, ts) for blob in blobs])

# Compute proof for these blobs

blobs_bytes = b''.join(blobs)

proof = ckzg.compute_aggregate_kzg_proof(blobs_bytes, ts)

# Verify proof

assert ckzg.verify_aggregate_kzg_proof(blobs_bytes, kzg_commitments, proof, ts), 'verify failed'

# Verification fails at wrong value

other = b'x' if not blobs_bytes.startswith(b'x') else b'y'
other_bytes = other + blobs_bytes[1:]

assert not ckzg.verify_aggregate_kzg_proof(other_bytes, kzg_commitments, proof, ts), 'verify succeeded incorrectly'

print('tests passed')
