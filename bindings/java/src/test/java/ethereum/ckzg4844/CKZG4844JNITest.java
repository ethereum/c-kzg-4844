package ethereum.ckzg4844;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ethereum.ckzg4844.CKZG4844JNI.Preset;
import ethereum.ckzg4844.CKZGException.CKZGError;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

public class CKZG4844JNITest {

  private static final Preset PRESET;

  private static final Map<Preset, String> TRUSTED_SETUP_FILE_BY_PRESET = Map.of(Preset.MAINNET,
      "../../src/trusted_setup.txt", Preset.MINIMAL, "../../src/trusted_setup_4.txt");

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

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  public void computesAndVerifiesProofs(final boolean useTrustedSetupFile) {

    loadTrustedSetup(useTrustedSetupFile);

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
  public void checkCustomExceptionIsThrownAsExpected() {

    loadTrustedSetup();

    final byte[] blob = TestUtils.createNonCanonicalBlob();

    final CKZGException exception = assertThrows(CKZGException.class,
        () -> CKZG4844JNI.blobToKzgCommitment(blob));

    assertEquals(CKZGError.C_KZG_BADARGS, exception.getError());
    assertEquals("There was an error while converting blob to commitment.",
        exception.getErrorMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void passingInvalidLengthForBlobsThrowsAnException() {

    loadTrustedSetup();

    CKZGException exception = assertThrows(CKZGException.class,
        () -> CKZG4844JNI.blobToKzgCommitment(new byte[0]));

    assertEquals(CKZGError.C_KZG_BADARGS, exception.getError());
    assertEquals(String.format("Invalid blob size. Expected %d bytes but got 0.",
            CKZG4844JNI.getBytesPerBlob()),
        exception.getErrorMessage());

    exception = assertThrows(CKZGException.class,
        () -> CKZG4844JNI.computeAggregateKzgProof(new byte[123], 1));

    assertEquals(CKZGError.C_KZG_BADARGS, exception.getError());
    assertEquals(String.format("Invalid blobs size. Expected %d bytes but got 123.",
            CKZG4844JNI.getBytesPerBlob()),
        exception.getErrorMessage());

    exception = assertThrows(CKZGException.class,
        () -> CKZG4844JNI.verifyAggregateKzgProof(new byte[42], TestUtils.createRandomCommitment(),
            2, TestUtils.createRandomProof(2)));

    assertEquals(CKZGError.C_KZG_BADARGS, exception.getError());
    assertEquals(String.format("Invalid blobs size. Expected %d bytes but got 42.",
            CKZG4844JNI.getBytesPerBlob() * 2),
        exception.getErrorMessage());

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

  private static void loadTrustedSetup(final boolean useFile) {
    if (useFile) {
      loadTrustedSetup();
    } else {
      final LoadTrustedSetupParameters parameters = TestUtils.createLoadTrustedSetupParameters(
          TRUSTED_SETUP_FILE_BY_PRESET.get(PRESET));
      CKZG4844JNI.loadTrustedSetup(parameters.getG1(), parameters.getG1Count(), parameters.getG2(),
          parameters.getG2Count());
    }
  }

  private static void loadTrustedSetup() {
    CKZG4844JNI.loadTrustedSetup(TRUSTED_SETUP_FILE_BY_PRESET.get(PRESET));
  }

  private static Stream<VerifyKzgProofParameters> getVerifyKzgProofTestVectors() {
    loadTrustedSetup();
    return TestUtils.getVerifyKzgProofTestVectors().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }
}
