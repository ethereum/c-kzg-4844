package ethereum.ckzg4844;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import ethereum.ckzg4844.test_formats.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;

public class TestUtils {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(new YAMLFactory());

  private static final Random RANDOM = new Random();

  private static final String BLOB_TO_KZG_COMMITMENT_TESTS = "../../tests/blob_to_kzg_commitment/";
  private static final String COMPUTE_KZG_PROOF_TESTS = "../../tests/compute_kzg_proof/";
  private static final String COMPUTE_BLOB_KZG_PROOF_TESTS = "../../tests/compute_blob_kzg_proof/";
  private static final String VERIFY_KZG_PROOF_TESTS = "../../tests/verify_kzg_proof/";
  private static final String VERIFY_BLOB_KZG_PROOF_TESTS = "../../tests/verify_blob_kzg_proof/";
  private static final String VERIFY_BLOB_KZG_PROOF_BATCH_TESTS =
      "../../tests/verify_blob_kzg_proof_batch/";
  private static final String COMPUTE_CELLS_AND_KZG_PROOFS_TESTS =
      "../../tests/compute_cells_and_kzg_proofs/";
  private static final String RECOVER_CELLS_AND_KZG_PROOFS_TESTS =
      "../../tests/recover_cells_and_kzg_proofs/";
  private static final String VERIFY_CELL_KZG_PROOF_BATCH_TESTS =
      "../../tests/verify_cell_kzg_proof_batch/";

  public static byte[] flatten(final byte[]... bytes) {
    final int capacity = Arrays.stream(bytes).mapToInt(b -> b.length).sum();
    final ByteBuffer buffer = ByteBuffer.allocate(capacity);
    Arrays.stream(bytes).forEach(buffer::put);
    return buffer.array();
  }

  public static byte[] createRandomBlob() {
    final byte[][] blob =
        IntStream.range(0, CKZG4844JNI.FIELD_ELEMENTS_PER_BLOB)
            .mapToObj(__ -> randomBLSFieldElement())
            .map(fieldElement -> fieldElement.toArray(ByteOrder.BIG_ENDIAN))
            .toArray(byte[][]::new);
    return flatten(blob);
  }

  public static byte[] createRandomBlobs(final int count) {
    final byte[][] blobs =
        IntStream.range(0, count).mapToObj(__ -> createRandomBlob()).toArray(byte[][]::new);
    return flatten(blobs);
  }

  public static byte[] createRandomProof() {
    return CKZG4844JNI.computeBlobKZGProof(createRandomBlob(), createRandomCommitment());
  }

  public static byte[] createRandomProofs(final int count) {
    final byte[][] proofs =
        IntStream.range(0, count).mapToObj(__ -> createRandomProof()).toArray(byte[][]::new);
    return flatten(proofs);
  }

  public static byte[] createRandomCommitment() {
    return CKZG4844JNI.blobToKZGCommitment(createRandomBlob());
  }

  public static byte[] createRandomCommitments(final int count) {
    final byte[][] commitments =
        IntStream.range(0, count).mapToObj(__ -> createRandomCommitment()).toArray(byte[][]::new);
    return flatten(commitments);
  }

  public static byte[] createNonCanonicalBlob() {
    final byte[][] blob =
        IntStream.range(0, CKZG4844JNI.FIELD_ELEMENTS_PER_BLOB)
            .mapToObj(__ -> UInt256.valueOf(CKZG4844JNI.BLS_MODULUS.add(BigInteger.valueOf(42))))
            .map(greaterThanModulus -> greaterThanModulus.toArray(ByteOrder.BIG_ENDIAN))
            .toArray(byte[][]::new);
    return flatten(blob);
  }

  public static List<BlobToKZGCommitmentTest> getBlobToKZGCommitmentTests() {
    final Stream.Builder<BlobToKZGCommitmentTest> tests = Stream.builder();
    List<String> testFiles = getTestFiles(BLOB_TO_KZG_COMMITMENT_TESTS);
    assert !testFiles.isEmpty();

    try {
      for (String testFile : testFiles) {
        String data = Files.readString(Path.of(testFile));
        BlobToKZGCommitmentTest test = OBJECT_MAPPER.readValue(data, BlobToKZGCommitmentTest.class);
        tests.add(test);
      }
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }

    return tests.build().collect(Collectors.toList());
  }

  public static List<ComputeKZGProofTest> getComputeKZGProofTests() {
    final Stream.Builder<ComputeKZGProofTest> tests = Stream.builder();
    List<String> testFiles = getTestFiles(COMPUTE_KZG_PROOF_TESTS);
    assert !testFiles.isEmpty();

    try {
      for (String testFile : testFiles) {
        String jsonData = Files.readString(Path.of(testFile));
        ComputeKZGProofTest test = OBJECT_MAPPER.readValue(jsonData, ComputeKZGProofTest.class);
        tests.add(test);
      }
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }

    return tests.build().collect(Collectors.toList());
  }

  public static List<ComputeBlobKZGProofTest> getComputeBlobKZGProofTests() {
    final Stream.Builder<ComputeBlobKZGProofTest> tests = Stream.builder();
    List<String> testFiles = getTestFiles(COMPUTE_BLOB_KZG_PROOF_TESTS);
    assert !testFiles.isEmpty();

    try {
      for (String testFile : testFiles) {
        String jsonData = Files.readString(Path.of(testFile));
        ComputeBlobKZGProofTest test =
            OBJECT_MAPPER.readValue(jsonData, ComputeBlobKZGProofTest.class);
        tests.add(test);
      }
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }

    return tests.build().collect(Collectors.toList());
  }

  public static List<VerifyKZGProofTest> getVerifyKZGProofTests() {
    final Stream.Builder<VerifyKZGProofTest> tests = Stream.builder();
    List<String> testFiles = getTestFiles(VERIFY_KZG_PROOF_TESTS);
    assert !testFiles.isEmpty();

    try {
      for (String testFile : testFiles) {
        String jsonData = Files.readString(Path.of(testFile));
        VerifyKZGProofTest test = OBJECT_MAPPER.readValue(jsonData, VerifyKZGProofTest.class);
        tests.add(test);
      }
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }

    return tests.build().collect(Collectors.toList());
  }

  public static List<VerifyBlobKZGProofTest> getVerifyBlobKZGProofTests() {
    final Stream.Builder<VerifyBlobKZGProofTest> tests = Stream.builder();
    List<String> testFiles = getTestFiles(VERIFY_BLOB_KZG_PROOF_TESTS);
    assert !testFiles.isEmpty();

    try {
      for (String testFile : testFiles) {
        String jsonData = Files.readString(Path.of(testFile));
        VerifyBlobKZGProofTest test =
            OBJECT_MAPPER.readValue(jsonData, VerifyBlobKZGProofTest.class);
        tests.add(test);
      }
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }

    return tests.build().collect(Collectors.toList());
  }

  public static List<VerifyBlobKZGProofBatchTest> getVerifyBlobKZGProofBatchTests() {
    final Stream.Builder<VerifyBlobKZGProofBatchTest> tests = Stream.builder();
    List<String> testFiles = getTestFiles(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS);
    assert !testFiles.isEmpty();

    try {
      for (String testFile : testFiles) {
        String jsonData = Files.readString(Path.of(testFile));
        VerifyBlobKZGProofBatchTest test =
            OBJECT_MAPPER.readValue(jsonData, VerifyBlobKZGProofBatchTest.class);
        tests.add(test);
      }
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }

    return tests.build().collect(Collectors.toList());
  }

  public static List<ComputeCellsAndKZGProofsTest> getComputeCellsAndKZGProofsTests() {
    final Stream.Builder<ComputeCellsAndKZGProofsTest> tests = Stream.builder();
    List<String> testFiles = getTestFiles(COMPUTE_CELLS_AND_KZG_PROOFS_TESTS);
    assert !testFiles.isEmpty();

    try {
      for (String testFile : testFiles) {
        String jsonData = Files.readString(Path.of(testFile));
        ComputeCellsAndKZGProofsTest test =
            OBJECT_MAPPER.readValue(jsonData, ComputeCellsAndKZGProofsTest.class);
        tests.add(test);
      }
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }

    return tests.build().collect(Collectors.toList());
  }

  public static List<RecoverCellsAndKZGProofsTest> getRecoverCellsAndKZGProofsTests() {
    final Stream.Builder<RecoverCellsAndKZGProofsTest> tests = Stream.builder();
    List<String> testFiles = getTestFiles(RECOVER_CELLS_AND_KZG_PROOFS_TESTS);
    assert !testFiles.isEmpty();

    try {
      for (String testFile : testFiles) {
        String jsonData = Files.readString(Path.of(testFile));
        RecoverCellsAndKZGProofsTest test =
            OBJECT_MAPPER.readValue(jsonData, RecoverCellsAndKZGProofsTest.class);
        tests.add(test);
      }
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }

    return tests.build().collect(Collectors.toList());
  }

  public static List<VerifyCellKZGProofBatchTest> getVerifyCellKZGProofBatchTests() {
    final Stream.Builder<VerifyCellKZGProofBatchTest> tests = Stream.builder();
    List<String> testFiles = getTestFiles(VERIFY_CELL_KZG_PROOF_BATCH_TESTS);
    assert !testFiles.isEmpty();

    try {
      for (String testFile : testFiles) {
        String jsonData = Files.readString(Path.of(testFile));
        VerifyCellKZGProofBatchTest test =
            OBJECT_MAPPER.readValue(jsonData, VerifyCellKZGProofBatchTest.class);
        tests.add(test);
      }
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }

    return tests.build().collect(Collectors.toList());
  }

  public static LoadTrustedSetupParameters createLoadTrustedSetupParameters(
      final String trustedSetup) {
    try (final BufferedReader reader = new BufferedReader(new FileReader(trustedSetup))) {
      final int g1Count = Integer.parseInt(reader.readLine());
      final int g2Count = Integer.parseInt(reader.readLine());

      final ByteBuffer g1MonomialBytes = ByteBuffer.allocate(g1Count * CKZG4844JNI.BYTES_PER_G1);
      final ByteBuffer g1LagrangeBytes = ByteBuffer.allocate(g1Count * CKZG4844JNI.BYTES_PER_G1);
      final ByteBuffer g2MonomialBytes = ByteBuffer.allocate(g2Count * CKZG4844JNI.BYTES_PER_G2);

      for (int i = 0; i < g1Count; i++) {
        g1LagrangeBytes.put(Bytes.fromHexString(reader.readLine()).toArray());
      }
      for (int i = 0; i < g2Count; i++) {
        g2MonomialBytes.put(Bytes.fromHexString(reader.readLine()).toArray());
      }
      for (int i = 0; i < g1Count; i++) {
        g1MonomialBytes.put(Bytes.fromHexString(reader.readLine()).toArray());
      }

      return new LoadTrustedSetupParameters(
          g1MonomialBytes.array(), g1LagrangeBytes.array(), g2MonomialBytes.array());
    } catch (final IOException ex) {
      throw new UncheckedIOException(ex);
    }
  }

  private static UInt256 randomBLSFieldElement() {
    final BigInteger attempt = new BigInteger(CKZG4844JNI.BLS_MODULUS.bitLength(), RANDOM);
    if (attempt.compareTo(CKZG4844JNI.BLS_MODULUS) < 0) {
      return UInt256.valueOf(attempt);
    }
    return randomBLSFieldElement();
  }

  public static byte[] randomBLSFieldElementBytes() {
    return randomBLSFieldElement().toArray(ByteOrder.BIG_ENDIAN);
  }

  public static List<String> getFiles(String path) {
    try {
      try (Stream<Path> stream = Files.list(Paths.get(path))) {
        return stream.map(Path::toString).sorted().collect(Collectors.toList());
      }
    } catch (final IOException ex) {
      throw new UncheckedIOException(ex);
    }
  }

  public static List<String> getTestFiles(String path) {
    List<String> testFiles = new ArrayList<>();
    for (final String suite : getFiles(path)) {
      for (final String test : getFiles(suite)) {
        testFiles.addAll(getFiles(test));
      }
    }
    return testFiles;
  }
}
