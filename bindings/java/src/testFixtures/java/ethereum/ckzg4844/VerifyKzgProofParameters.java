package ethereum.ckzg4844;

public class VerifyKzgProofParameters {

  public static final VerifyKzgProofParameters ZERO;

  static {
    final byte[] commitment = new byte[CKZG4844JNI.BYTES_PER_COMMITMENT];
    commitment[0] = (byte) 0xc0;
    final byte[] z = new byte[32];
    final byte[] y = new byte[32];
    final byte[] proof = new byte[CKZG4844JNI.BYTES_PER_PROOF];
    proof[0] = (byte) 0xc0;
    ZERO = new VerifyKzgProofParameters(commitment, z, y, proof);
  }

  private final byte[] commitment;
  private final byte[] z;
  private final byte[] y;
  private final byte[] proof;

  public VerifyKzgProofParameters(
      final byte[] commitment, final byte[] z, final byte[] y, final byte[] proof) {
    this.commitment = commitment;
    this.z = z;
    this.y = y;
    this.proof = proof;
  }

  public byte[] getCommitment() {
    return commitment;
  }

  public byte[] getZ() {
    return z;
  }

  public byte[] getY() {
    return y;
  }

  public byte[] getProof() {
    return proof;
  }
}
