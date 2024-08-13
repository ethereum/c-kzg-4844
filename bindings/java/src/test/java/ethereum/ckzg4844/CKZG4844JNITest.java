package ethereum.ckzg4844;

import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_CELL;
import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_COMMITMENT;
import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_PROOF;
import static ethereum.ckzg4844.CKZG4844JNI.CELLS_PER_EXT_BLOB;
import static ethereum.ckzg4844.CKZGException.CKZGError.C_KZG_BADARGS;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ethereum.ckzg4844.test_formats.*;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
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

  private static final String TRUSTED_SETUP_FILE = "../../src/trusted_setup.txt";
  private static final String TRUSTED_SETUP_RESOURCE = "/trusted-setups/trusted_setup.txt";

  static {
    CKZG4844JNI.loadNativeLibrary();
  }

  @ParameterizedTest
  @MethodSource("getBlobToKZGCommitmentTests")
  public void blobToKZGCommitmentTests(final BlobToKZGCommitmentTest test) {
    try {
      byte[] commitment = CKZG4844JNI.blobToKZGCommitment(test.getInput().getBlob());
      assertArrayEquals(test.getOutput(), commitment);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getComputeKZGProofTests")
  public void computeKZGProofTests(final ComputeKZGProofTest test) {
    try {
      ProofAndY proofAndY =
          CKZG4844JNI.computeKZGProof(test.getInput().getBlob(), test.getInput().getZ());
      assertArrayEquals(test.getOutput().getProof(), proofAndY.getProof());
      assertArrayEquals(test.getOutput().getY(), proofAndY.getY());
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getComputeBlobKZGProofTests")
  public void computeBlobKZGProofTests(final ComputeBlobKZGProofTest test) {
    try {
      byte[] proof =
          CKZG4844JNI.computeBlobKZGProof(
              test.getInput().getBlob(), test.getInput().getCommitment());
      assertArrayEquals(test.getOutput(), proof);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyKZGProofTests")
  public void verifyKZGProofTests(final VerifyKZGProofTest test) {
    try {
      boolean valid =
          CKZG4844JNI.verifyKZGProof(
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
  @MethodSource("getVerifyBlobKZGProofTests")
  public void verifyBlobKZGProofTests(final VerifyBlobKZGProofTest test) {
    try {
      boolean valid =
          CKZG4844JNI.verifyBlobKZGProof(
              test.getInput().getBlob(),
              test.getInput().getCommitment(),
              test.getInput().getProof());
      assertEquals(test.getOutput(), valid);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyBlobKZGProofBatchTests")
  public void verifyBlobKZGProofBatchTests(final VerifyBlobKZGProofBatchTest test) {
    try {
      int count = test.getInput().getBlobs().length / CKZG4844JNI.BYTES_PER_BLOB;
      boolean valid =
          CKZG4844JNI.verifyBlobKZGProofBatch(
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
  @MethodSource("getComputeCellsAndKZGProofsTests")
  public void verifyComputeCellsAndKZGProofsTests(final ComputeCellsAndKZGProofsTest test) {
    try {
      CellsAndProofs cellsAndProofs =
          CKZG4844JNI.computeCellsAndKZGProofs(test.getInput().getBlob());
      assertArrayEquals(test.getOutput().getCells(), cellsAndProofs.getCells());
      assertArrayEquals(test.getOutput().getProofs(), cellsAndProofs.getProofs());
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getRecoverCellsAndKZGProofsTests")
  public void recoverCellsAndKZGProofsTests(final RecoverCellsAndKZGProofsTest test) {
    try {
      final CellsAndProofs recoveredCellsAndProofs =
          CKZG4844JNI.recoverCellsAndKZGProofs(
              test.getInput().getCellIndices(), test.getInput().getCells());
      assertArrayEquals(test.getOutput().getCells(), recoveredCellsAndProofs.getCells());
      assertArrayEquals(test.getOutput().getProofs(), recoveredCellsAndProofs.getProofs());
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @MethodSource("getVerifyCellKZGProofBatchTests")
  public void verifyCellKZGProofBatchTests(final VerifyCellKZGProofBatchTest test) {
    try {
      boolean valid =
          CKZG4844JNI.verifyCellKZGProofBatch(
              test.getInput().getCommitments(),
              test.getInput().getCellIndices(),
              test.getInput().getCells(),
              test.getInput().getProofs());
      assertEquals(test.getOutput(), valid);
    } catch (CKZGException ex) {
      assertNull(test.getOutput());
    }
  }

  @ParameterizedTest
  @EnumSource(TrustedSetupSource.class)
  public void testVerifyBlobKZGProofBatch(final TrustedSetupSource trustedSetupSource) {
    loadTrustedSetup(trustedSetupSource);
    final int count = 3;
    final byte[][] blobsArray = new byte[count][];
    final byte[][] commitmentsArray = new byte[count][];
    final byte[][] proofsArray = new byte[count][];
    IntStream.range(0, count)
        .forEach(
            i -> {
              blobsArray[i] = TestUtils.createRandomBlob();
              commitmentsArray[i] = CKZG4844JNI.blobToKZGCommitment(blobsArray[i]);
              proofsArray[i] = CKZG4844JNI.computeBlobKZGProof(blobsArray[i], commitmentsArray[i]);
            });
    final byte[] blobs = TestUtils.flatten(blobsArray);
    final byte[] commitments = TestUtils.flatten(commitmentsArray);
    final byte[] proofs = TestUtils.flatten(proofsArray);

    assertTrue(CKZG4844JNI.verifyBlobKZGProofBatch(blobs, commitments, proofs, count));

    final byte[] fakeBlobs = TestUtils.createRandomBlobs(count);
    assertFalse(CKZG4844JNI.verifyBlobKZGProofBatch(fakeBlobs, commitments, proofs, count));
    final byte[] fakeCommitments = TestUtils.createRandomCommitments(count);
    assertFalse(CKZG4844JNI.verifyBlobKZGProofBatch(blobs, fakeCommitments, proofs, count));
    final byte[] fakeProofs = TestUtils.createRandomProofs(count);
    assertFalse(CKZG4844JNI.verifyBlobKZGProofBatch(blobs, commitments, fakeProofs, count));

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void checkComputeKZGProof() {
    loadTrustedSetup();
    final byte[] blob = TestUtils.createRandomBlob();
    final byte[] z_bytes = TestUtils.randomBLSFieldElementBytes();
    final ProofAndY proofAndY = CKZG4844JNI.computeKZGProof(blob, z_bytes);
    assertEquals(BYTES_PER_PROOF, proofAndY.getProof().length);
    assertEquals(CKZG4844JNI.BYTES_PER_FIELD_ELEMENT, proofAndY.getY().length);
    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void checkRecoverCellsAndKZGProofs() {
    loadTrustedSetup();
    final byte[] blob = TestUtils.createRandomBlob();
    final CellsAndProofs cellsAndProofs = CKZG4844JNI.computeCellsAndKZGProofs(blob);
    final byte[] cells = cellsAndProofs.getCells();
    final byte[] proofs = cellsAndProofs.getProofs();
    final byte[] partialCells = new byte[BYTES_PER_CELL * CELLS_PER_EXT_BLOB / 2];
    System.arraycopy(cells, 0, partialCells, 0, partialCells.length);
    final long[] cellIndices = LongStream.range(0, CELLS_PER_EXT_BLOB / 2).toArray();
    final CellsAndProofs recoveredCellsAndProofs =
        CKZG4844JNI.recoverCellsAndKZGProofs(cellIndices, partialCells);
    assertArrayEquals(cells, recoveredCellsAndProofs.getCells());
    assertArrayEquals(proofs, recoveredCellsAndProofs.getProofs());
    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void checkVerifyCellBatch() {
    loadTrustedSetup();

    final int count = 6;
    final int commitmentsLength = CELLS_PER_EXT_BLOB * BYTES_PER_COMMITMENT;
    final int cellsLength = CELLS_PER_EXT_BLOB * BYTES_PER_CELL;
    final int proofsLength = CELLS_PER_EXT_BLOB * BYTES_PER_PROOF;

    final byte[] commitments = new byte[count * commitmentsLength];
    final CellsAndProofs[] data = new CellsAndProofs[count];
    final long[] cellIndices = new long[count * CELLS_PER_EXT_BLOB];
    final byte[] cells = new byte[count * cellsLength];
    final byte[] proofs = new byte[count * proofsLength];

    for (int i = 0; i < count; i++) {
      final byte[] blob = TestUtils.createRandomBlob();
      final byte[] commitment = CKZG4844JNI.blobToKZGCommitment(blob);
      for (int j = 0; j < CELLS_PER_EXT_BLOB; j++) {
        System.arraycopy(
            commitment,
            0,
            commitments,
            i * commitmentsLength + j * BYTES_PER_COMMITMENT,
            BYTES_PER_COMMITMENT);
      }
      data[i] = CKZG4844JNI.computeCellsAndKZGProofs(blob);
      System.arraycopy(data[i].getCells(), 0, cells, i * cellsLength, cellsLength);
      System.arraycopy(data[i].getProofs(), 0, proofs, i * proofsLength, proofsLength);
    }

    for (int i = 0; i < count; i++) {
      for (int j = 0; j < CELLS_PER_EXT_BLOB; j++) {
        final int index = i * CELLS_PER_EXT_BLOB + j;
        cellIndices[index] = j;
      }
    }

    assertTrue(CKZG4844JNI.verifyCellKZGProofBatch(commitments, cellIndices, cells, proofs));
    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void checkComputeBlobKZGProof() {
    loadTrustedSetup();
    final byte[] blob = TestUtils.createRandomBlob();
    final byte[] commitment = TestUtils.createRandomCommitment();
    final byte[] proof = CKZG4844JNI.computeBlobKZGProof(blob, commitment);
    assertEquals(BYTES_PER_PROOF, proof.length);
    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void checkCustomExceptionIsThrownAsExpected() {

    loadTrustedSetup();

    final byte[] blob = TestUtils.createNonCanonicalBlob();

    final CKZGException exception =
        assertThrows(CKZGException.class, () -> CKZG4844JNI.blobToKZGCommitment(blob));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals("There was an error in blobToKZGCommitment.", exception.getErrorMessage());

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
            () -> CKZG4844JNI.verifyBlobKZGProofBatch(blobs, commitments, proofs, count));
    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        "Invalid commitments size. Expected 96 bytes but got 144.", exception.getErrorMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void passingInvalidLengthForBlobsThrowsAnException() {

    loadTrustedSetup();

    CKZGException exception =
        assertThrows(CKZGException.class, () -> CKZG4844JNI.blobToKZGCommitment(new byte[0]));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        String.format(
            "Invalid blob size. Expected %d bytes but got 0.", CKZG4844JNI.BYTES_PER_BLOB),
        exception.getErrorMessage());

    exception =
        assertThrows(
            CKZGException.class,
            () -> CKZG4844JNI.computeBlobKZGProof(new byte[123], new byte[32]));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        String.format(
            "Invalid blob size. Expected %d bytes but got 123.", CKZG4844JNI.BYTES_PER_BLOB),
        exception.getErrorMessage());

    exception =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.computeBlobKZGProof(
                    new byte[CKZG4844JNI.BYTES_PER_BLOB], new byte[49]));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        "Invalid commitment size. Expected 48 bytes but got 49.", exception.getErrorMessage());

    exception =
        assertThrows(
            CKZGException.class,
            () ->
                CKZG4844JNI.verifyBlobKZGProofBatch(
                    new byte[42],
                    TestUtils.createRandomCommitments(2),
                    TestUtils.createRandomProofs(2),
                    2));

    assertEquals(C_KZG_BADARGS, exception.getError());
    assertEquals(
        String.format(
            "Invalid blobs size. Expected %d bytes but got 42.", CKZG4844JNI.BYTES_PER_BLOB * 2),
        exception.getErrorMessage());

    CKZG4844JNI.freeTrustedSetup();
  }

  @Test
  public void throwsIfMethodIsUsedWithoutLoadingTrustedSetup() {

    final RuntimeException exception =
        assertThrows(
            RuntimeException.class,
            () -> CKZG4844JNI.blobToKZGCommitment(TestUtils.createRandomBlob()));

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
    CKZG4844JNI.loadTrustedSetup(TRUSTED_SETUP_FILE, 0);
  }

  private static void loadTrustedSetupFromParameters() {
    final LoadTrustedSetupParameters parameters =
        TestUtils.createLoadTrustedSetupParameters(TRUSTED_SETUP_FILE);
    CKZG4844JNI.loadTrustedSetup(
        parameters.getG1MonomialBytes(),
        parameters.getG1LagrangeBytes(),
        parameters.getG2MonomialBytes(),
        0);
  }

  public static void loadTrustedSetupFromResource() {
    CKZG4844JNI.loadTrustedSetupFromResource(TRUSTED_SETUP_RESOURCE, CKZG4844JNITest.class, 0);
  }

  private static Stream<BlobToKZGCommitmentTest> getBlobToKZGCommitmentTests() {
    loadTrustedSetup();
    return TestUtils.getBlobToKZGCommitmentTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<ComputeKZGProofTest> getComputeKZGProofTests() {
    loadTrustedSetup();
    return TestUtils.getComputeKZGProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<ComputeBlobKZGProofTest> getComputeBlobKZGProofTests() {
    loadTrustedSetup();
    return TestUtils.getComputeBlobKZGProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyKZGProofTest> getVerifyKZGProofTests() {
    loadTrustedSetup();
    return TestUtils.getVerifyKZGProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyBlobKZGProofTest> getVerifyBlobKZGProofTests() {
    loadTrustedSetup();
    return TestUtils.getVerifyBlobKZGProofTests().stream().onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyBlobKZGProofBatchTest> getVerifyBlobKZGProofBatchTests() {
    loadTrustedSetup();
    return TestUtils.getVerifyBlobKZGProofBatchTests().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<ComputeCellsAndKZGProofsTest> getComputeCellsAndKZGProofsTests() {
    loadTrustedSetup();
    return TestUtils.getComputeCellsAndKZGProofsTests().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<RecoverCellsAndKZGProofsTest> getRecoverCellsAndKZGProofsTests() {
    loadTrustedSetup();
    return TestUtils.getRecoverCellsAndKZGProofsTests().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }

  private static Stream<VerifyCellKZGProofBatchTest> getVerifyCellKZGProofBatchTests() {
    loadTrustedSetup();
    return TestUtils.getVerifyCellKZGProofBatchTests().stream()
        .onClose(CKZG4844JNI::freeTrustedSetup);
  }
}
