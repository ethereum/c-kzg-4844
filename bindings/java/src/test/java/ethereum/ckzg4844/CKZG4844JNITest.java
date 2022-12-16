package ethereum.ckzg4844;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ethereum.ckzg4844.CKZG4844JNI.Preset;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class CKZG4844JNITest {

  private static final Preset PRESET;

  static {
    PRESET = Optional.ofNullable(System.getenv("PRESET")).map(String::toUpperCase)
        .map(Preset::valueOf).orElse(Preset.MAINNET);
    CKZG4844JNI.loadNativeLibrary(PRESET);
  }

  @Test
  public void getsTheConfiguredFieldElementsPerBlob() {
    assertEquals(PRESET.fieldElementsPerBlob, CKZG4844JNI.getFieldElementsPerBlob());
    assertEquals(PRESET.fieldElementsPerBlob * CKZG4844JNI.BYTES_PER_FIELD_ELEMENT,
        CKZG4844JNI.getBytesPerBlob());
  }

  @Test
  public void computesAndVerifiesProofs() {

    loadTrustedSetup();

    final int count = 3;

    final byte[][] blobsArray = new byte[count][];
    final byte[][] commitmentsArray = new byte[count][];
    IntStream.range(0, count).forEach(i -> {
      blobsArray[i] = TestUtils.createRandomBlob();
      commitmentsArray[i] = CKZG4844JNI.blobToKzgCommitment(blobsArray[i]);
    });
    final byte[] blobs = TestUtils.flatten(blobsArray);
    final byte[] commitments = TestUtils.flatten(commitmentsArray);

    assertEquals(CKZG4844JNI.BYTES_PER_COMMITMENT * count, commitments.length);

    final byte[] proof = CKZG4844JNI.computeAggregateKzgProof(blobs, count);

    assertEquals(CKZG4844JNI.BYTES_PER_PROOF, proof.length);

    assertTrue(CKZG4844JNI.verifyAggregateKzgProof(blobs, commitments, count, proof));

    final byte[] fakeProof = TestUtils.createRandomProof(count);
    assertFalse(CKZG4844JNI.verifyAggregateKzgProof(blobs, commitments, count, fakeProof));

    final byte[] fakeBlobs = TestUtils.createRandomBlobs(count);
    assertFalse(CKZG4844JNI.verifyAggregateKzgProof(fakeBlobs, commitments, count, proof));

    final byte[] fakeCommitments = TestUtils.createRandomCommitments(count);
    assertFalse(CKZG4844JNI.verifyAggregateKzgProof(blobs, fakeCommitments, count, proof));

    CKZG4844JNI.freeTrustedSetup();

  }

  @ParameterizedTest(name = "{index}")
  @MethodSource("getVerifyKzgProofTestVectors")
  public void testVerifyKzgProof(final VerifyKzgProofParameters parameters) {
    assertTrue(
        CKZG4844JNI.verifyKzgProof(parameters.getCommitment(), parameters.getZ(), parameters.getY(),
            parameters.getProof()));
  }

  @Test
  public void passingZeroElementArraysForBlobsDoesNotCauseSegmentationFaultErrors() {

    loadTrustedSetup();

    RuntimeException exception = assertThrows(RuntimeException.class,
        () -> CKZG4844JNI.blobToKzgCommitment(new byte[0]));

    assertEquals("Passing byte array with 0 elements for a blob is not supported.",
        exception.getMessage());

    exception = assertThrows(RuntimeException.class,
        () -> CKZG4844JNI.verifyAggregateKzgProof(new byte[0], TestUtils.createRandomCommitment(),
            1,
            TestUtils.createRandomProof(1)));

    assertEquals("Passing byte array with 0 elements for blobs is not supported.",
        exception.getMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void throwsIfMethodIsUsedWithoutLoadingTrustedSetup() {

    final RuntimeException exception = assertThrows(RuntimeException.class,
        () -> CKZG4844JNI.blobToKzgCommitment(TestUtils.createRandomBlob()));

    assertExceptionIsTrustedSetupIsNotLoaded(exception);

  }

  @Test
  public void throwsIfSetupIsLoadedTwice() {

    loadTrustedSetup();

    final RuntimeException exception = assertThrows(RuntimeException.class,
        CKZG4844JNITest::loadTrustedSetup);

    assertEquals("Trusted Setup is already loaded. Free it before loading a new one.",
        exception.getMessage());

    CKZG4844JNI.freeTrustedSetup();

  }

  @Test
  public void throwsIfTryToFreeTrustedSetupWithoutLoadingIt() {

    final RuntimeException exception = assertThrows(RuntimeException.class,
        CKZG4844JNI::freeTrustedSetup);

    assertExceptionIsTrustedSetupIsNotLoaded(exception);

  }

  private void assertExceptionIsTrustedSetupIsNotLoaded(final RuntimeException exception) {
    assertEquals("Trusted Setup is not loaded.", exception.getMessage());
  }

  private static void loadTrustedSetup() {
    if (PRESET.equals(Preset.MINIMAL)) {
      CKZG4844JNI.loadTrustedSetup("../../src/trusted_setup_4.txt");
    } else {
      CKZG4844JNI.loadTrustedSetup("../../src/trusted_setup.txt");
    }
  }

  private static Stream<VerifyKzgProofParameters> getVerifyKzgProofTestVectors() {
    loadTrustedSetup();
    return TestUtils.getVerifyKzgProofTestVectors().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }
}
