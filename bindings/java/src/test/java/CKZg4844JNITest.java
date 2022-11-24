import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CKZg4844JNITest {

  private final Random random = new Random();

  @BeforeEach
  public void setUp() {
    CKzg4844JNI.loadTrustedSetup("../../src/trusted_setup.txt");
  }

  @AfterEach
  public void cleanUp() {
    CKzg4844JNI.freeTrustedSetup();
  }

  @Test
  public void computesAndVerifiesProofs() {

    final byte[] blob = createRandomBlob();
    final byte[] blob2 = createRandomBlob();

    assertEquals(blob.length, CKzg4844JNI.BYTES_PER_BLOB);
    assertEquals(blob2.length, CKzg4844JNI.BYTES_PER_BLOB);

    final byte[] commitment = CKzg4844JNI.blobToKzgCommitment(blob);
    final byte[] commitment2 = CKzg4844JNI.blobToKzgCommitment(blob2);

    assertEquals(commitment.length, CKzg4844JNI.BYTES_PER_COMMITMENT);
    assertEquals(commitment2.length, CKzg4844JNI.BYTES_PER_COMMITMENT);

    // flatten blobs and commitments
    final byte[] blobs = flatten(blob, blob2);
    final byte[] commitments = flatten(commitment, commitment2);

    final byte[] proof = CKzg4844JNI.computeAggregateKzgProof(blobs, 2);

    assertEquals(proof.length, CKzg4844JNI.BYTES_PER_PROOF);

    assertTrue(CKzg4844JNI.verifyAggregateKzgProof(blobs, commitments, 2, proof));

  }

  @Test
  public void verifiesPointEvaluationPrecompile() {

    final byte[] commitment = new byte[48];
    commitment[0] = (byte) 0xc0;
    final byte[] z = new byte[32];
    final byte[] y = new byte[32];
    final byte[] proof = new byte[48];
    proof[0] = (byte) 0xc0;

    assertTrue(CKzg4844JNI.verifyKzgProof(commitment, z, y, proof));

  }

  private byte[] createRandomBlob() {
    final byte[] blob = new byte[CKzg4844JNI.BYTES_PER_BLOB];
    random.nextBytes(blob);
    return blob;
  }

  private byte[] flatten(byte[]... bytes) {
    final int capacity = Arrays.stream(bytes).mapToInt(b -> b.length).sum();
    final ByteBuffer buffer = ByteBuffer.allocate(capacity);
    Arrays.stream(bytes).forEach(buffer::put);
    return buffer.array();
  }
}
