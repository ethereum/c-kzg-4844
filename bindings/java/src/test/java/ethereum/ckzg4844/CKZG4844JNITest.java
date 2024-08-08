package ethereum.ckzg4844;

import static ethereum.ckzg4844.CKZGException.CKZGError.C_KZG_BADARGS;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ethereum.ckzg4844.test_formats.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class CKZG4844JNITest {
  private enum TrustedSetupSource {
    FILE,
    PARAMETERS,
    RESOURCE
  }

  private static final String TRUSTED_SETUP_FILE = "../../src/trusted_setup.txt";
  private static final String TRUSTED_SETUP_RESOURCE = "/trusted-setups/trusted_setup.txt";

  static {
    CKZG4844JNI.loadNativeLibrary();
  }

  @ParameterizedTest
  @MethodSource("getBlobToKzgCommitmentTests")
  public void blobToKzgCommitmentTests(final BlobToKzgCommitmentTest test) {
    try {
      byte[] commitment = CKZG4844JNI.blobToKzgCommitment(test.getInput().getBlob());
      assertArrayEquals(test.getOutput(), commitment);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getComputeKzgProofTests")
  public void computeKzgProofTests(final ComputeKzgProofTest test) {
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
  public void computeBlobKzgProofTests(final ComputeBlobKzgProofTest test) {
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
  public void verifyKzgProofTests(final VerifyKzgProofTest test) {
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
  public void verifyBlobKzgProofTests(final VerifyBlobKzgProofTest test) {
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
  public void verifyBlobKzgProofBatchTests(final VerifyBlobKzgProofBatchTest test) {
    try {
      int count = test.getInput().getBlobs().length / CKZG4844JNI.BYTES_PER_BLOB;
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
  @MethodSource("getComputeCellsAndKzgProofsTests")
  public void verifyComputeCellsAndKzgProofsTests(final ComputeCellsAndKzgProofsTest test) {
    try {
      CellsAndProofs cellsAndProofs =
          CKZG4844JNI.computeCellsAndKzgProofs(test.getInput().getBlob());
      assertArrayEquals(test.getOutput().getCells(), cellsAndProofs.getCells());
      assertArrayEquals(test.getOutput().getProofs(), cellsAndProofs.getProofs());
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getRecoverCellsAndKzgProofsTests")
  public void recoverCellsAndKzgProofsTests(final RecoverCellsAndKzgProofsTest test) {
    try {
      final CellsAndProofs recoveredCellsAndProofs =
          CKZG4844JNI.recoverCellsAndKzgProofs(
              test.getInput().getCellIndices(), test.getInput().getCells());
      assertArrayEquals(test.getOutput().getCells(), recoveredCellsAndProofs.getCells());
      assertArrayEquals(test.getOutput().getProofs(), recoveredCellsAndProofs.getProofs());
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyCellKzgProofBatchTests")
  public void verifyCellKzgProofBatchTests(final VerifyCellKzgProofBatchTest test) {
    try {
      boolean valid =
          CKZG4844JNI.verifyCellKzgProofBatch(
              test.getInput().getCommitments(),
              test.getInput().getCellIndices(),
              test.getInput().getCells(),
              test.getInput().getProofs());
      assertEquals(test.getOutput(), valid);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
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
        TestUtils.createLoadTrustedSetupParameters(TRUSTED_SETUP_FILE);

    // wrong g1 monomial points
    CKZGException exception =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.loadTrustedSetup(
                    new byte[27], // wrong g1 monomial
                    parameters.getG1LagrangeBytes(),
                    parameters.getG2MonomialBytes(),
                    0));
    assertEquals(C_KZG_BADARGS, exception.getError());
    assertTrue(
        exception
            .getErrorMessage()
            .contains("There was an error while loading the Trusted Setup."));

    // wrong g1 lagrange points
    exception =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.loadTrustedSetup(
                    parameters.getG1MonomialBytes(),
                    new byte[27], // wrong g1 lagrange
                    parameters.getG2MonomialBytes(),
                    0));
    assertEquals(C_KZG_BADARGS, exception.getError());
    assertTrue(
        exception
            .getErrorMessage()
            .contains("There was an error while loading the Trusted Setup."));

    // wrong g2 monomial points
    exception =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.loadTrustedSetup(
                    parameters.getG1MonomialBytes(),
                    parameters.getG1LagrangeBytes(),
                    new byte[27], // wrong g1 lagrange
                    0));
    assertEquals(C_KZG_BADARGS, exception.getError());
    assertTrue(
        exception
            .getErrorMessage()
            .contains("There was an error while loading the Trusted Setup."));
  }

  private void assertExceptionIsTrustedSetupIsNotLoaded(final RuntimeException exception) {
    assertEquals("Trusted Setup is not loaded.", exception.getMessage());
  }

  private static void loadTrustedSetup() {
    CKZG4844JNI.loadTrustedSetup(TRUSTED_SETUP_FILE, 0);
  }

  public static void loadTrustedSetupFromResource() {
    CKZG4844JNI.loadTrustedSetupFromResource(TRUSTED_SETUP_RESOURCE, CKZG4844JNITest.class, 0);
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

  private static Stream<ComputeCellsAndKzgProofsTest> getComputeCellsAndKzgProofsTests() {
    loadTrustedSetup();
    return TestUtils.getComputeCellsAndKzgProofsTests().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<RecoverCellsAndKzgProofsTest> getRecoverCellsAndKzgProofsTests() {
    loadTrustedSetup();
    return TestUtils.getRecoverCellsAndKzgProofsTests().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyCellKzgProofBatchTest> getVerifyCellKzgProofBatchTests() {
    loadTrustedSetup();
    return TestUtils.getVerifyCellKzgProofBatchTests().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }
}
