package ethereum.ckzg4844;

import static ethereum.ckzg4844.CKZGException.CKZGError.C_KZG_BADARGS;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ethereum.ckzg4844.CKZG4844JNI.Preset;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

public class CKZG4844JNITest {
  private enum TrustedSetupSource {
    FILE,
    PARAMETERS,
    RESOURCE
  }

  private static final Preset PRESET;

  private static final Map<Preset, String> TRUSTED_SETUP_FILE_BY_PRESET =
      Map.of(
          Preset.MAINNET,
          "../../src/trusted_setup.txt",
          Preset.MINIMAL,
          "../../src/trusted_setup_4.txt");

  private static final Map<Preset, String> TRUSTED_SETUP_RESOURCE_BY_PRESET =
      Map.of(
          Preset.MAINNET,
          "/trusted-setups/trusted_setup.txt",
          Preset.MINIMAL,
          "/trusted-setups/trusted_setup_4.txt");

  static {
    PRESET =
        Optional.ofNullable(System.getenv("PRESET"))
            .map(String::toUpperCase)
            .map(Preset::valueOf)
            .orElse(Preset.MAINNET);
    CKZG4844JNI.loadNativeLibrary(PRESET);
  }

  @ParameterizedTest
  @MethodSource("getBlobToKzgCommitmentTests")
  public void blobToKzgCommitmentTests(final BlobToKzgCommitmentTest test) {
    if (PRESET != Preset.MAINNET) return;

    try {
      byte[] commitment = CKZG4844JNI.blobToKzgCommitment(test.getInput().getBlob());
      assertArrayEquals(commitment, test.getOutput().getCommitment());
    } catch (CKZGException ex) {
      assertNull(test.getOutput().getCommitment());
    }
  }

  @ParameterizedTest
  @MethodSource("getComputeKzgProofTests")
  public void computeKzgProofTests(final ComputeKzgProofTest test) {
    if (PRESET != Preset.MAINNET) return;

    try {
      byte[] proof =
          CKZG4844JNI.computeKzgProof(test.getInput().getBlob(), test.getInput().getInputPoint());
      assertArrayEquals(proof, test.getOutput().getProof());
    } catch (CKZGException ex) {
      assertNull(test.getOutput().getProof());
    }
  }

  @ParameterizedTest
  @MethodSource("getComputeBlobKzgProofTests")
  public void computeBlobKzgProofTests(final ComputeBlobKzgProofTest test) {
    if (PRESET != Preset.MAINNET) return;

    try {
      byte[] proof = CKZG4844JNI.computeBlobKzgProof(test.getInput().getBlob());
      assertArrayEquals(proof, test.getOutput().getProof());
    } catch (CKZGException ex) {
      assertNull(test.getOutput().getProof());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyKzgProofTests")
  public void verifyKzgProofTests(final VerifyKzgProofTest test) {
    if (PRESET != Preset.MAINNET) return;

    try {
      boolean valid =
          CKZG4844JNI.verifyKzgProof(
              test.getInput().getCommitment(),
              test.getInput().getInputPoint(),
              test.getInput().getClaimedValue(),
              test.getInput().getProof());
      assertEquals(valid, test.getOutput().getValid());
    } catch (CKZGException ex) {
      assertNull(test.getOutput().getValid());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyBlobKzgProofTests")
  public void verifyBlobKzgProofTests(final VerifyBlobKzgProofTest test) {
    if (PRESET != Preset.MAINNET) return;

    try {
      boolean valid =
          CKZG4844JNI.verifyBlobKzgProof(
              test.getInput().getBlob(),
              test.getInput().getCommitment(),
              test.getInput().getProof());
      assertEquals(valid, test.getOutput().getValid());
    } catch (CKZGException ex) {
      assertNull(test.getOutput().getValid());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyBlobKzgProofBatchTests")
  public void verifyBlobKzgProofBatchTests(final VerifyBlobKzgProofBatchTest test) {
    if (PRESET != Preset.MAINNET) return;

    try {
      int count = test.getInput().getBlobs().length / CKZG4844JNI.getBytesPerBlob();
      boolean valid =
          CKZG4844JNI.verifyBlobKzgProofBatch(
              test.getInput().getBlobs(),
              test.getInput().getCommitments(),
              test.getInput().getProofs(),
              count);
      assertEquals(valid, test.getOutput().getValid());
    } catch (CKZGException ex) {
      assertNull(test.getOutput().getValid());
    }
  }

  @Test
  public void getsTheConfiguredFieldElementsPerBlob() {
    assertEquals(PRESET.fieldElementsPerBlob, CKZG4844JNI.getFieldElementsPerBlob());
    assertEquals(
        PRESET.fieldElementsPerBlob * CKZG4844JNI.BYTES_PER_FIELD_ELEMENT,
        CKZG4844JNI.getBytesPerBlob());
  }

  @ParameterizedTest
  @EnumSource(TrustedSetupSource.class)
  public void testVerifyBlobKzgProofBatch(final TrustedSetupSource trustedSetupSource) {
    loadTrustedSetup(trustedSetupSource);
    final int count = 3;
    final byte[][] blobsArray = new byte[count][];
    final byte[][] commitmentsArray = new byte[count][];
    final byte[][] proofsArray = new byte[count][];
    IntStream.range(0, count)
        .forEach(
            i -> {
              blobsArray[i] = TestUtils.createRandomBlob();
              commitmentsArray[i] = CKZG4844JNI.blobToKzgCommitment(blobsArray[i]);
              proofsArray[i] = CKZG4844JNI.computeBlobKzgProof(blobsArray[i]);
            });
    final byte[] blobs = TestUtils.flatten(blobsArray);
    final byte[] commitments = TestUtils.flatten(commitmentsArray);
    final byte[] proofs = TestUtils.flatten(proofsArray);

    assertTrue(CKZG4844JNI.verifyBlobKzgProofBatch(blobs, commitments, proofs, count));

    final byte[] fakeBlobs = TestUtils.createRandomBlobs(count);
    assertFalse(CKZG4844JNI.verifyBlobKzgProofBatch(fakeBlobs, commitments, proofs, count));
    final byte[] fakeCommitments = TestUtils.createRandomCommitments(count);
    assertFalse(CKZG4844JNI.verifyBlobKzgProofBatch(blobs, fakeCommitments, proofs, count));
    final byte[] fakeProofs = TestUtils.createRandomProofs(count);
    assertFalse(CKZG4844JNI.verifyBlobKzgProofBatch(blobs, commitments, fakeProofs, count));

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void checkComputeKzgProof() {
    loadTrustedSetup();
    final byte[] blob = TestUtils.createRandomBlob();
    final byte[] z_bytes = TestUtils.randomBLSFieldElementBytes();
    final byte[] proof = CKZG4844JNI.computeKzgProof(blob, z_bytes);
    assertEquals(CKZG4844JNI.BYTES_PER_PROOF, proof.length);
    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void checkComputeBlobKzgProof() {
    loadTrustedSetup();
    final byte[] blob = TestUtils.createRandomBlob();
    final byte[] proof = CKZG4844JNI.computeBlobKzgProof(blob);
    assertEquals(CKZG4844JNI.BYTES_PER_PROOF, proof.length);
    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void checkCustomExceptionIsThrownAsExpected() {

    loadTrustedSetup();

    final byte[] blob = TestUtils.createNonCanonicalBlob();

    final CKZGException exception =
        assertThrows(CKZGException.class, () -> CKZG4844JNI.blobToKzgCommitment(blob));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals("There was an error in blobToKzgCommitment.", exception.getErrorMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void passingDifferentLengthForCommitmentsThrowsAnException() {
    loadTrustedSetup();

    final int count = 2;
    final byte[] blobs = TestUtils.createRandomBlobs(count);
    final byte[] proofs = TestUtils.createRandomProofs(count);
    // different length for commitments
    final byte[] commitments = TestUtils.createRandomCommitments(3);

    final CKZGException exception =
        assertThrows(
            CKZGException.class,
            () -> CKZG4844JNI.verifyBlobKzgProofBatch(blobs, commitments, proofs, count));
    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        "Invalid commitments size. Expected 96 bytes but got 144.", exception.getErrorMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void passingInvalidLengthForBlobsThrowsAnException() {

    loadTrustedSetup();

    CKZGException exception =
        assertThrows(CKZGException.class, () -> CKZG4844JNI.blobToKzgCommitment(new byte[0]));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        String.format(
            "Invalid blob size. Expected %d bytes but got 0.", CKZG4844JNI.getBytesPerBlob()),
        exception.getErrorMessage());

    exception =
        assertThrows(CKZGException.class, () -> CKZG4844JNI.computeBlobKzgProof(new byte[123]));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        String.format(
            "Invalid blob size. Expected %d bytes but got 123.", CKZG4844JNI.getBytesPerBlob()),
        exception.getErrorMessage());

    exception =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.verifyBlobKzgProofBatch(
                    new byte[42],
                    TestUtils.createRandomCommitments(2),
                    TestUtils.createRandomProofs(2),
                    2));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        String.format(
            "Invalid blobs size. Expected %d bytes but got 42.", CKZG4844JNI.getBytesPerBlob() * 2),
        exception.getErrorMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void throwsIfMethodIsUsedWithoutLoadingTrustedSetup() {

    final RuntimeException exception =
        assertThrows(
            RuntimeException.class,
            () -> CKZG4844JNI.blobToKzgCommitment(TestUtils.createRandomBlob()));

    assertExceptionIsTrustedSetupIsNotLoaded(exception);
  }

  @Test
  public void throwsIfSetupIsLoadedTwice() {

    loadTrustedSetup();

    final RuntimeException exception =
        assertThrows(RuntimeException.class, CKZG4844JNITest::loadTrustedSetup);

    assertEquals(
        "Trusted Setup is already loaded. Free it before loading a new one.",
        exception.getMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void throwsIfTryToFreeTrustedSetupWithoutLoadingIt() {

    final RuntimeException exception =
        assertThrows(RuntimeException.class, CKZG4844JNI::freeTrustedSetup);

    assertExceptionIsTrustedSetupIsNotLoaded(exception);
  }

  @Test
  public void shouldThrowExceptionOnIncorrectTrustedSetupParameters() {
    final LoadTrustedSetupParameters parameters =
        TestUtils.createLoadTrustedSetupParameters(TRUSTED_SETUP_FILE_BY_PRESET.get(PRESET));

    // wrong g1Count
    CKZGException exception =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.loadTrustedSetup(
                    parameters.getG1(),
                    parameters.getG1Count() + 1,
                    parameters.getG2(),
                    parameters.getG2Count()));
    assertEquals(C_KZG_BADARGS, exception.getError());
    assertTrue(exception.getErrorMessage().contains("Invalid g1 size."));

    // wrong g2Count
    exception =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.loadTrustedSetup(
                    parameters.getG1(),
                    parameters.getG1Count(),
                    parameters.getG2(),
                    parameters.getG2Count() + 1));
    assertEquals(C_KZG_BADARGS, exception.getError());
    assertTrue(exception.getErrorMessage().contains("Invalid g2 size."));
  }

  @Test
  public void shouldThrowExceptionOnIncorrectTrustedSetupFromFile() {
    final Preset incorrectPreset = PRESET == Preset.MAINNET ? Preset.MINIMAL : Preset.MAINNET;
    final CKZGException exception =
        assertThrows(
            CKZGException.class,
            () -> CKZG4844JNI.loadTrustedSetup(TRUSTED_SETUP_FILE_BY_PRESET.get(incorrectPreset)));
    assertEquals(C_KZG_BADARGS, exception.getError());
  }

  private void assertExceptionIsTrustedSetupIsNotLoaded(final RuntimeException exception) {
    assertEquals("Trusted Setup is not loaded.", exception.getMessage());
  }

  private static void loadTrustedSetup(final TrustedSetupSource trustedSetupSource) {
    switch (trustedSetupSource) {
      case FILE:
        loadTrustedSetup();
        break;
      case PARAMETERS:
        loadTrustedSetupFromParameters();
        break;
      case RESOURCE:
        loadTrustedSetupFromResource();
        break;
    }
  }

  private static void loadTrustedSetup() {
    CKZG4844JNI.loadTrustedSetup(TRUSTED_SETUP_FILE_BY_PRESET.get(PRESET));
  }

  private static void loadTrustedSetupFromParameters() {
    final LoadTrustedSetupParameters parameters =
        TestUtils.createLoadTrustedSetupParameters(TRUSTED_SETUP_FILE_BY_PRESET.get(PRESET));
    CKZG4844JNI.loadTrustedSetup(
        parameters.getG1(), parameters.getG1Count(), parameters.getG2(), parameters.getG2Count());
  }

  public static void loadTrustedSetupFromResource() {
    CKZG4844JNI.loadTrustedSetupFromResource(
        TRUSTED_SETUP_RESOURCE_BY_PRESET.get(PRESET), CKZG4844JNITest.class);
  }

  private static Stream<BlobToKzgCommitmentTest> getBlobToKzgCommitmentTests() {
    loadTrustedSetup();
    return TestUtils.getBlobToKzgCommitmentTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<ComputeKzgProofTest> getComputeKzgProofTests() {
    loadTrustedSetup();
    return TestUtils.getComputeKzgProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<ComputeBlobKzgProofTest> getComputeBlobKzgProofTests() {
    loadTrustedSetup();
    return TestUtils.getComputeBlobKzgProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyKzgProofTest> getVerifyKzgProofTests() {
    loadTrustedSetup();
    return TestUtils.getVerifyKzgProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyBlobKzgProofTest> getVerifyBlobKzgProofTests() {
    loadTrustedSetup();
    return TestUtils.getVerifyBlobKzgProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyBlobKzgProofBatchTest> getVerifyBlobKzgProofBatchTests() {
    loadTrustedSetup();
    return TestUtils.getVerifyBlobKzgProofBatchTests().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }
}
