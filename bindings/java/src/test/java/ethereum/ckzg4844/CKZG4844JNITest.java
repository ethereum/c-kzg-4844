package ethereum.ckzg4844;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ethereum.ckzg4844.CKZG4844JNI.Preset;
import ethereum.ckzg4844.CKZGException.CKZGError;
import java.nio.file.Files;
import java.nio.file.Paths;
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
          "/test-vectors/trusted_setup.txt",
          Preset.MINIMAL,
          "/test-vectors/trusted_setup_4.txt");

  private static final String BLOB_TO_KZG_COMMITMENT_TESTS = "../../tests/blob_to_kzg_commitment/";
  private static final String COMPUTE_KZG_PROOF_TESTS = "../../tests/compute_kzg_proof/";
  private static final String COMPUTE_BLOB_KZG_PROOF_TESTS = "../../tests/compute_blob_kzg_proof/";
  private static final String VERIFY_KZG_PROOF_TESTS = "../../tests/verify_kzg_proof/";
  private static final String VERIFY_BLOB_KZG_PROOF_TESTS = "../../tests/verify_blob_kzg_proof/";
  private static final String VERIFY_BLOB_KZG_PROOF_BATCH_TESTS =
      "../../tests/verify_blob_kzg_proof_batch/";

  static {
    PRESET =
        Optional.ofNullable(System.getenv("PRESET"))
            .map(String::toUpperCase)
            .map(Preset::valueOf)
            .orElse(Preset.MAINNET);
    CKZG4844JNI.loadNativeLibrary(PRESET);
  }

  @Test
  public void blobToKzgCommitmentTests() {
    if (PRESET != Preset.MAINNET) return;
    loadTrustedSetup();

    for (String test : TestUtils.getFiles(BLOB_TO_KZG_COMMITMENT_TESTS)) {
      byte[] blob = TestUtils.getBytes(Paths.get(test, "blob.txt"));
      try {
        byte[] commitment = CKZG4844JNI.blobToKzgCommitment(blob);
        byte[] expectedCommitment = TestUtils.getBytes(Paths.get(test, "commitment.txt"));
        assertArrayEquals(commitment, expectedCommitment);
      } catch (CKZGException ex) {
        assertFalse(Files.exists(Paths.get(test, "commitment.txt")));
      }
    }

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void computeKzgProofTests() {
    if (PRESET != Preset.MAINNET) return;
    loadTrustedSetup();

    for (String test : TestUtils.getFiles(COMPUTE_KZG_PROOF_TESTS)) {
      byte[] blob = TestUtils.getBytes(Paths.get(test, "blob.txt"));
      byte[] inputPoint = TestUtils.getBytes(Paths.get(test, "input_point.txt"));
      try {
        byte[] proof = CKZG4844JNI.computeKzgProof(blob, inputPoint);
        byte[] expectedProof = TestUtils.getBytes(Paths.get(test, "proof.txt"));
        assertArrayEquals(proof, expectedProof);
      } catch (CKZGException ex) {
        assertFalse(Files.exists(Paths.get(test, "proof.txt")));
      }
    }

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void computeBlobKzgProofTests() {
    if (PRESET != Preset.MAINNET) return;
    loadTrustedSetup();

    for (String test : TestUtils.getFiles(COMPUTE_BLOB_KZG_PROOF_TESTS)) {
      byte[] blob = TestUtils.getBytes(Paths.get(test, "blob.txt"));
      try {
        byte[] proof = CKZG4844JNI.computeBlobKzgProof(blob);
        byte[] expectedProof = TestUtils.getBytes(Paths.get(test, "proof.txt"));
        assertArrayEquals(proof, expectedProof);
      } catch (CKZGException ex) {
        assertFalse(Files.exists(Paths.get(test, "proof.txt")));
      }
    }

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void verifyKzgProofTests() {
    if (PRESET != Preset.MAINNET) return;
    loadTrustedSetup();

    for (String test : TestUtils.getFiles(VERIFY_KZG_PROOF_TESTS)) {
      byte[] commitment = TestUtils.getBytes(Paths.get(test, "commitment.txt"));
      byte[] inputPoint = TestUtils.getBytes(Paths.get(test, "input_point.txt"));
      byte[] claimedValue = TestUtils.getBytes(Paths.get(test, "claimed_value.txt"));
      byte[] proof = TestUtils.getBytes(Paths.get(test, "proof.txt"));
      try {
        boolean ok = CKZG4844JNI.verifyKzgProof(commitment, inputPoint, claimedValue, proof);
        boolean expectedOk = TestUtils.getBoolean(Paths.get(test, "ok.txt"));
        assertEquals(ok, expectedOk);
      } catch (CKZGException ex) {
        assertFalse(Files.exists(Paths.get(test, "ok.txt")));
      }
    }

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void verifyBlobKzgProofTests() {
    if (PRESET != Preset.MAINNET) return;
    loadTrustedSetup();

    for (String test : TestUtils.getFiles(VERIFY_BLOB_KZG_PROOF_TESTS)) {
      byte[] blob = TestUtils.getBytes(Paths.get(test, "blob.txt"));
      byte[] commitment = TestUtils.getBytes(Paths.get(test, "commitment.txt"));
      byte[] proof = TestUtils.getBytes(Paths.get(test, "proof.txt"));
      try {
        boolean ok = CKZG4844JNI.verifyBlobKzgProof(blob, commitment, proof);
        boolean expectedOk = TestUtils.getBoolean(Paths.get(test, "ok.txt"));
        assertEquals(ok, expectedOk);
      } catch (CKZGException ex) {
        assertFalse(Files.exists(Paths.get(test, "ok.txt")));
      }
    }

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void verifyBlobKzgProofBatchTests() {
    if (PRESET != Preset.MAINNET) return;
    loadTrustedSetup();

    for (String test : TestUtils.getFiles(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS)) {
      byte[] blobs =
          TestUtils.flatten(
              TestUtils.getFiles(Paths.get(test, "blobs").toString()).stream()
                  .map(Paths::get)
                  .map(TestUtils::getBytes)
                  .toArray(byte[][]::new));
      byte[] commitments =
          TestUtils.flatten(
              TestUtils.getFiles(Paths.get(test, "commitments").toString()).stream()
                  .map(Paths::get)
                  .map(TestUtils::getBytes)
                  .toArray(byte[][]::new));
      byte[] proofs =
          TestUtils.flatten(
              TestUtils.getFiles(Paths.get(test, "proofs").toString()).stream()
                  .map(Paths::get)
                  .map(TestUtils::getBytes)
                  .toArray(byte[][]::new));

      try {
        boolean ok =
            CKZG4844JNI.verifyBlobKzgProofBatch(
                blobs, commitments, proofs, blobs.length / CKZG4844JNI.getBytesPerBlob());
        boolean expectedOk = TestUtils.getBoolean(Paths.get(test, "ok.txt"));
        assertEquals(ok, expectedOk);
      } catch (CKZGException ex) {
        assertFalse(Files.exists(Paths.get(test, "ok.txt")));
      }
    }

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void getsTheConfiguredFieldElementsPerBlob() {
    assertEquals(PRESET.fieldElementsPerBlob, CKZG4844JNI.getFieldElementsPerBlob());
    assertEquals(
        PRESET.fieldElementsPerBlob * CKZG4844JNI.BYTES_PER_FIELD_ELEMENT,
        CKZG4844JNI.getBytesPerBlob());
  }

  @ParameterizedTest(name = "{index}")
  @MethodSource("getVerifyKzgProofTestVectors")
  public void testVerifyKzgProof(final VerifyKzgProofParameters parameters) {
    assertTrue(
        CKZG4844JNI.verifyKzgProof(
            parameters.getCommitment(),
            parameters.getZ(),
            parameters.getY(),
            parameters.getProof()));
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

    assertEquals(CKZGError.C_KZG_BADARGS, exception.getError());
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
    assertEquals(CKZGError.C_KZG_BADARGS, exception.getError());
    assertEquals(
        "Invalid commitments size. Expected 96 bytes but got 144.", exception.getErrorMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void passingInvalidLengthForBlobsThrowsAnException() {

    loadTrustedSetup();

    CKZGException exception =
        assertThrows(CKZGException.class, () -> CKZG4844JNI.blobToKzgCommitment(new byte[0]));

    assertEquals(CKZGError.C_KZG_BADARGS, exception.getError());
    assertEquals(
        String.format(
            "Invalid blob size. Expected %d bytes but got 0.", CKZG4844JNI.getBytesPerBlob()),
        exception.getErrorMessage());

    exception =
        assertThrows(CKZGException.class, () -> CKZG4844JNI.computeBlobKzgProof(new byte[123]));

    assertEquals(CKZGError.C_KZG_BADARGS, exception.getError());
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

    assertEquals(CKZGError.C_KZG_BADARGS, exception.getError());
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
    final CKZGException ckzgException =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.loadTrustedSetup(
                    parameters.getG1(),
                    parameters.getG1Count() + 1,
                    parameters.getG2(),
                    parameters.getG2Count()));
    assertTrue(ckzgException.getMessage().contains("C_KZG_BADARGS"));
  }

  @Test
  public void shouldThrowExceptionOnIncorrectTrustedSetupFromFile() {
    final Preset incorrectPreset = PRESET == Preset.MAINNET ? Preset.MINIMAL : Preset.MAINNET;
    final CKZGException ckzgException =
        assertThrows(
            CKZGException.class,
            () -> CKZG4844JNI.loadTrustedSetup(TRUSTED_SETUP_FILE_BY_PRESET.get(incorrectPreset)));
    assertTrue(ckzgException.getMessage().contains("C_KZG_BADARGS"));
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

  private static Stream<VerifyKzgProofParameters> getVerifyKzgProofTestVectors() {
    loadTrustedSetup();
    return TestUtils.getVerifyKzgProofTestVectors().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }
}
