package ethereum.ckzg4844;

import static ethereum.ckzg4844.CKZGException.CKZGError.C_KZG_BADARGS;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ethereum.ckzg4844.CKZG4844JNI.Preset;
import ethereum.ckzg4844.test_formats.*;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

public class CKZG4844JNITest {
  private enum TrustedSetupSource {
    FILE,
    PARAMETERS,
    RESOURCE
  }

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

  private static final Map<Preset, String> OLD_TRUSTED_SETUP_FILE_BY_PRESET =
      Map.of(
          Preset.MAINNET,
          "./src/testFixtures/resources/trusted-setups/trusted_setup_old.txt",
          Preset.MINIMAL,
          "./src/testFixtures/resources/trusted-setups/trusted_setup_4_old.txt");

  static {
    CKZG4844JNI.loadNativeLibrary();
  }

  @ParameterizedTest
  @MethodSource("getBlobToKzgCommitmentTests")
  public void blobToKzgCommitmentTests(BlobToKzgCommitmentTest test) {
    try {
      byte[] commitment = CKZG4844JNI.blobToKzgCommitment(test.getInput().getBlob());
      assertArrayEquals(test.getOutput(), commitment);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getComputeKzgProofTests")
  public void computeKzgProofTests(ComputeKzgProofTest test) {
    try {
      ProofAndY proofAndY =
          CKZG4844JNI.computeKzgProof(test.getInput().getBlob(), test.getInput().getZ());
      assertArrayEquals(test.getOutput().getProof(), proofAndY.getProof());
      assertArrayEquals(test.getOutput().getY(), proofAndY.getY());
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getComputeBlobKzgProofTests")
  public void computeBlobKzgProofTests(ComputeBlobKzgProofTest test) {
    try {
      byte[] proof =
          CKZG4844JNI.computeBlobKzgProof(
              test.getInput().getBlob(), test.getInput().getCommitment());
      assertArrayEquals(test.getOutput(), proof);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyKzgProofTests")
  public void verifyKzgProofTests(VerifyKzgProofTest test) {
    try {
      boolean valid =
          CKZG4844JNI.verifyKzgProof(
              test.getInput().getCommitment(),
              test.getInput().getZ(),
              test.getInput().getY(),
              test.getInput().getProof());
      assertEquals(test.getOutput(), valid);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyBlobKzgProofTests")
  public void verifyBlobKzgProofTests(VerifyBlobKzgProofTest test) {
    try {
      boolean valid =
          CKZG4844JNI.verifyBlobKzgProof(
              test.getInput().getBlob(),
              test.getInput().getCommitment(),
              test.getInput().getProof());
      assertEquals(test.getOutput(), valid);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyBlobKzgProofBatchTests")
  public void verifyBlobKzgProofBatchTests(VerifyBlobKzgProofBatchTest test) {
    try {
      int count = test.getInput().getBlobs().length / CKZG4844JNI.getBytesPerBlob();
      boolean valid =
          CKZG4844JNI.verifyBlobKzgProofBatch(
              test.getInput().getBlobs(),
              test.getInput().getCommitments(),
              test.getInput().getProofs(),
              count);
      assertEquals(test.getOutput(), valid);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @EnumSource(Preset.class)
  public void getsTheConfiguredFieldElementsPerBlob(Preset preset) {
    loadTrustedSetup(preset);
    assertEquals(preset.fieldElementsPerBlob, CKZG4844JNI.getFieldElementsPerBlob());
    assertEquals(
        preset.fieldElementsPerBlob * CKZG4844JNI.BYTES_PER_FIELD_ELEMENT,
        CKZG4844JNI.getBytesPerBlob());
    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void failsToGetFieldElementsPerBlobIfTrustedSetupIsNotLoaded() {
    RuntimeException exception =
        assertThrows(RuntimeException.class, CKZG4844JNI::getFieldElementsPerBlob);
    assertExceptionIsTrustedSetupIsNotLoaded(exception);
  }

  @ParameterizedTest
  @MethodSource("getTrustedSetupSources")
  public void testVerifyBlobKzgProofBatch(Preset preset, TrustedSetupSource trustedSetupSource) {
    loadTrustedSetup(preset, trustedSetupSource);
    int count = 3;
    byte[][] blobsArray = new byte[count][];
    byte[][] commitmentsArray = new byte[count][];
    byte[][] proofsArray = new byte[count][];
    IntStream.range(0, count)
        .forEach(
            i -> {
              blobsArray[i] = TestUtils.createRandomBlob();
              commitmentsArray[i] = CKZG4844JNI.blobToKzgCommitment(blobsArray[i]);
              proofsArray[i] = CKZG4844JNI.computeBlobKzgProof(blobsArray[i], commitmentsArray[i]);
            });
    byte[] blobs = TestUtils.flatten(blobsArray);
    byte[] commitments = TestUtils.flatten(commitmentsArray);
    byte[] proofs = TestUtils.flatten(proofsArray);

    assertTrue(CKZG4844JNI.verifyBlobKzgProofBatch(blobs, commitments, proofs, count));

    byte[] fakeBlobs = TestUtils.createRandomBlobs(count);
    assertFalse(CKZG4844JNI.verifyBlobKzgProofBatch(fakeBlobs, commitments, proofs, count));
    byte[] fakeCommitments = TestUtils.createRandomCommitments(count);
    assertFalse(CKZG4844JNI.verifyBlobKzgProofBatch(blobs, fakeCommitments, proofs, count));
    byte[] fakeProofs = TestUtils.createRandomProofs(count);
    assertFalse(CKZG4844JNI.verifyBlobKzgProofBatch(blobs, commitments, fakeProofs, count));

    CKZG4844JNI.freeTrustedSetup();
  }

  @ParameterizedTest
  @EnumSource(Preset.class)
  public void checkComputeKzgProof(Preset preset) {
    loadTrustedSetup(preset);
    byte[] blob = TestUtils.createRandomBlob();
    byte[] z_bytes = TestUtils.randomBLSFieldElementBytes();
    ProofAndY proofAndY = CKZG4844JNI.computeKzgProof(blob, z_bytes);
    assertEquals(CKZG4844JNI.BYTES_PER_PROOF, proofAndY.getProof().length);
    assertEquals(CKZG4844JNI.BYTES_PER_FIELD_ELEMENT, proofAndY.getY().length);
    CKZG4844JNI.freeTrustedSetup();
  }

  @ParameterizedTest
  @EnumSource(Preset.class)
  public void checkComputeBlobKzgProof(Preset preset) {
    loadTrustedSetup(preset);
    byte[] blob = TestUtils.createRandomBlob();
    byte[] commitment = TestUtils.createRandomCommitment();
    byte[] proof = CKZG4844JNI.computeBlobKzgProof(blob, commitment);
    assertEquals(CKZG4844JNI.BYTES_PER_PROOF, proof.length);
    CKZG4844JNI.freeTrustedSetup();
  }

  @ParameterizedTest
  @EnumSource(Preset.class)
  public void checkCustomExceptionIsThrownAsExpected(Preset preset) {

    loadTrustedSetup(preset);

    byte[] blob = TestUtils.createNonCanonicalBlob();

    CKZGException exception =
        assertThrows(CKZGException.class, () -> CKZG4844JNI.blobToKzgCommitment(blob));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals("There was an error in blobToKzgCommitment.", exception.getErrorMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @ParameterizedTest
  @EnumSource(Preset.class)
  public void passingDifferentLengthForCommitmentsThrowsAnException(Preset preset) {
    loadTrustedSetup(preset);

    int count = 2;
    byte[] blobs = TestUtils.createRandomBlobs(count);
    byte[] proofs = TestUtils.createRandomProofs(count);
    // different length for commitments
    byte[] commitments = TestUtils.createRandomCommitments(3);

    CKZGException exception =
        assertThrows(
            CKZGException.class,
            () -> CKZG4844JNI.verifyBlobKzgProofBatch(blobs, commitments, proofs, count));
    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        "Invalid commitments size. Expected 96 bytes but got 144.", exception.getErrorMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @ParameterizedTest
  @EnumSource(Preset.class)
  public void passingInvalidLengthForBlobsThrowsAnException(Preset preset) {

    loadTrustedSetup(preset);

    CKZGException exception =
        assertThrows(CKZGException.class, () -> CKZG4844JNI.blobToKzgCommitment(new byte[0]));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        String.format(
            "Invalid blob size. Expected %d bytes but got 0.", CKZG4844JNI.getBytesPerBlob()),
        exception.getErrorMessage());

    exception =
        assertThrows(
            CKZGException.class,
            () -> CKZG4844JNI.computeBlobKzgProof(new byte[123], new byte[32]));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        String.format(
            "Invalid blob size. Expected %d bytes but got 123.", CKZG4844JNI.getBytesPerBlob()),
        exception.getErrorMessage());

    exception =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.computeBlobKzgProof(
                    new byte[CKZG4844JNI.getBytesPerBlob()], new byte[49]));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        "Invalid commitment size. Expected 48 bytes but got 49.", exception.getErrorMessage());

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

    RuntimeException exception =
        assertThrows(
            RuntimeException.class,
            () -> CKZG4844JNI.blobToKzgCommitment(TestUtils.createRandomBlob()));

    assertExceptionIsTrustedSetupIsNotLoaded(exception);
  }

  @Test
  public void throwsIfSetupIsLoadedTwice() {

    loadTrustedSetup(Preset.MAINNET);

    RuntimeException exception =
        assertThrows(RuntimeException.class, () -> loadTrustedSetup(Preset.MAINNET));

    assertEquals(
        "Trusted Setup is already loaded. Free it before loading a new one.",
        exception.getMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void throwsIfTryToFreeTrustedSetupWithoutLoadingIt() {

    RuntimeException exception =
        assertThrows(RuntimeException.class, CKZG4844JNI::freeTrustedSetup);

    assertExceptionIsTrustedSetupIsNotLoaded(exception);
  }

  @ParameterizedTest
  @EnumSource(Preset.class)
  public void shouldThrowExceptionIfTrustedSetupIsNotInLagrangeForm(Preset preset) {
    CKZGException exception =
        assertThrows(
            CKZGException.class,
            () -> CKZG4844JNI.loadTrustedSetup(OLD_TRUSTED_SETUP_FILE_BY_PRESET.get(preset)));

    assertEquals(C_KZG_BADARGS, exception.getError());
  }

  @ParameterizedTest
  @EnumSource(Preset.class)
  public void shouldThrowExceptionOnIncorrectTrustedSetupParameters(Preset preset) {
    LoadTrustedSetupParameters parameters =
        TestUtils.createLoadTrustedSetupParameters(TRUSTED_SETUP_FILE_BY_PRESET.get(preset));

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

  private void assertExceptionIsTrustedSetupIsNotLoaded(RuntimeException exception) {
    assertEquals("Trusted Setup is not loaded.", exception.getMessage());
  }

  private static void loadTrustedSetup(Preset preset, TrustedSetupSource trustedSetupSource) {
    switch (trustedSetupSource) {
      case FILE:
        loadTrustedSetup(preset);
        break;
      case PARAMETERS:
        loadTrustedSetupFromParameters(preset);
        break;
      case RESOURCE:
        loadTrustedSetupFromResource(preset);
        break;
    }
  }

  private static void loadTrustedSetup(Preset preset) {
    CKZG4844JNI.loadTrustedSetup(TRUSTED_SETUP_FILE_BY_PRESET.get(preset));
  }

  private static void loadTrustedSetupFromParameters(Preset preset) {
    LoadTrustedSetupParameters parameters =
        TestUtils.createLoadTrustedSetupParameters(TRUSTED_SETUP_FILE_BY_PRESET.get(preset));
    CKZG4844JNI.loadTrustedSetup(
        parameters.getG1(), parameters.getG1Count(), parameters.getG2(), parameters.getG2Count());
  }

  private static void loadTrustedSetupFromResource(Preset preset) {
    CKZG4844JNI.loadTrustedSetupFromResource(
        TRUSTED_SETUP_RESOURCE_BY_PRESET.get(preset), CKZG4844JNITest.class);
  }

  private static Stream<BlobToKzgCommitmentTest> getBlobToKzgCommitmentTests() {
    loadTrustedSetup(Preset.MAINNET);
    return TestUtils.getBlobToKzgCommitmentTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<ComputeKzgProofTest> getComputeKzgProofTests() {
    loadTrustedSetup(Preset.MAINNET);
    return TestUtils.getComputeKzgProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<ComputeBlobKzgProofTest> getComputeBlobKzgProofTests() {
    loadTrustedSetup(Preset.MAINNET);
    return TestUtils.getComputeBlobKzgProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyKzgProofTest> getVerifyKzgProofTests() {
    loadTrustedSetup(Preset.MAINNET);
    return TestUtils.getVerifyKzgProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyBlobKzgProofTest> getVerifyBlobKzgProofTests() {
    loadTrustedSetup(Preset.MAINNET);
    return TestUtils.getVerifyBlobKzgProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyBlobKzgProofBatchTest> getVerifyBlobKzgProofBatchTests() {
    loadTrustedSetup(Preset.MAINNET);
    return TestUtils.getVerifyBlobKzgProofBatchTests().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<Arguments> getTrustedSetupSources() {
    return Arrays.stream(Preset.values())
        .flatMap(
            preset ->
                Arrays.stream(TrustedSetupSource.values())
                    .map(trustedSetupSource -> Arguments.of(preset, trustedSetupSource)));
  }
}
