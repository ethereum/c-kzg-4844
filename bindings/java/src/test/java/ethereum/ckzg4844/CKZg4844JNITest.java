package ethereum.ckzg4844;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class CKZg4844JNITest {

  private final Random random = new Random();

  @Test
  public void computesAndVerifiesProofs() {

    loadTrustedSetup();

    final byte[] blob = createRandomBlob();
    final byte[] blob2 = createRandomBlob();

    final byte[] commitment = CKzg4844JNI.blobToKzgCommitment(blob);
    final byte[] commitment2 = CKzg4844JNI.blobToKzgCommitment(blob2);

    assertEquals(CKzg4844JNI.BYTES_PER_COMMITMENT, commitment.length);
    assertEquals(CKzg4844JNI.BYTES_PER_COMMITMENT, commitment2.length);

    final byte[] blobs = flatten(blob, blob2);
    final byte[] commitments = flatten(commitment, commitment2);

    final byte[] proof = CKzg4844JNI.computeAggregateKzgProof(blobs, 2);

    assertEquals(CKzg4844JNI.BYTES_PER_PROOF, proof.length);

    assertTrue(CKzg4844JNI.verifyAggregateKzgProof(blobs, commitments, 2, proof));

    final byte[] fakeProof = createRandomProof(2);
    assertFalse(CKzg4844JNI.verifyAggregateKzgProof(blobs, commitments, 2, fakeProof));

    CKzg4844JNI.freeTrustedSetup();

  }

  @Test
  public void verifiesPointEvaluationPrecompile() {

    loadTrustedSetup();

    final byte[] commitment = new byte[48];
    commitment[0] = (byte) 0xc0;
    final byte[] z = new byte[32];
    final byte[] y = new byte[32];
    final byte[] proof = new byte[48];
    proof[0] = (byte) 0xc0;

    assertTrue(CKzg4844JNI.verifyKzgProof(commitment, z, y, proof));

    CKzg4844JNI.freeTrustedSetup();

  }

  @Disabled("Use for manually testing performance.")
  @Test
  public void testPerformance() {

    loadTrustedSetup();

    final int count = 100;

    final byte[] blobs = createRandomBlobs(count);
    final byte[] commitments = getCommitmentsForBlobs(blobs, count);

    long startTime = System.currentTimeMillis();
    final byte[] proof = CKzg4844JNI.computeAggregateKzgProof(blobs, count);
    long endTime = System.currentTimeMillis();

    System.out.printf("Computing aggregate proof for %d blobs took %d milliseconds%n", count,
        endTime - startTime);

    startTime = System.currentTimeMillis();
    boolean proofValidity = CKzg4844JNI.verifyAggregateKzgProof(blobs, commitments, count, proof);
    endTime = System.currentTimeMillis();

    assertTrue(proofValidity);

    System.out.printf("Verifying aggregate proof for %d blobs took %d milliseconds%n", count,
        endTime - startTime);

    CKzg4844JNI.freeTrustedSetup();

  }

  @Test
  public void throwsIfMethodIsUsedWithoutLoadingTrustedSetup() {

    final RuntimeException exception = assertThrows(RuntimeException.class,
        () -> CKzg4844JNI.blobToKzgCommitment(createRandomBlob()));

    assertExceptionIsTrustedSetupIsNotLoaded(exception);

  }

  @Test
  public void throwsIfSetupIsLoadedTwice() {

    loadTrustedSetup();

    final RuntimeException exception = assertThrows(RuntimeException.class, this::loadTrustedSetup);

    assertEquals("Trusted Setup is already loaded. Free it before loading a new one.",
        exception.getMessage());

    CKzg4844JNI.freeTrustedSetup();

  }

  @Test
  public void throwsIfTryToFreeTrustedSetupWithoutLoadingIt() {

    final RuntimeException exception = assertThrows(RuntimeException.class,
        CKzg4844JNI::freeTrustedSetup);

    assertExceptionIsTrustedSetupIsNotLoaded(exception);

  }

  private void assertExceptionIsTrustedSetupIsNotLoaded(final RuntimeException exception) {
    assertEquals("Trusted Setup is not loaded.", exception.getMessage());
  }

  private void loadTrustedSetup() {
    CKzg4844JNI.loadTrustedSetup("../../src/trusted_setup.txt");
  }

  private byte[] createRandomBlob() {
    final byte[] blob = new byte[CKzg4844JNI.BYTES_PER_BLOB];
    random.nextBytes(blob);
    return blob;
  }

  private byte[] createRandomBlobs(final int count) {
    final byte[][] blobs = IntStream.rangeClosed(1, count).mapToObj(__ -> createRandomBlob())
        .toArray(byte[][]::new);
    return flatten(blobs);
  }

  private byte[] createRandomProof(final int count) {
    return CKzg4844JNI.computeAggregateKzgProof(createRandomBlobs(count), count);
  }

  private byte[] getCommitmentsForBlobs(final byte[] blobs, final int count) {
    final byte[][] commitments = new byte[count][];
    IntStream.range(0, count).forEach(i -> {
      final byte[] blob = Arrays.copyOfRange(blobs, i * CKzg4844JNI.BYTES_PER_BLOB,
          (i + 1) * CKzg4844JNI.BYTES_PER_BLOB);
      commitments[i] = CKzg4844JNI.blobToKzgCommitment(blob);
    });
    return flatten(commitments);
  }

  private byte[] flatten(final byte[]... bytes) {
    final int capacity = Arrays.stream(bytes).mapToInt(b -> b.length).sum();
    final ByteBuffer buffer = ByteBuffer.allocate(capacity);
    Arrays.stream(bytes).forEach(buffer::put);
    return buffer.array();
  }
}
