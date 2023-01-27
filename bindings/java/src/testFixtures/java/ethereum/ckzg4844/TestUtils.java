package ethereum.ckzg4844;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;

public class TestUtils {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private static final Random RANDOM = new Random();

  public static byte[] flatten(final byte[]... bytes) {
    final int capacity = Arrays.stream(bytes).mapToInt(b -> b.length).sum();
    final ByteBuffer buffer = ByteBuffer.allocate(capacity);
    Arrays.stream(bytes).forEach(buffer::put);
    return buffer.array();
  }

  public static byte[] createRandomBlob() {
    final byte[][] blob = IntStream.range(0, CKZG4844JNI.getFieldElementsPerBlob())
        .mapToObj(__ -> randomBLSFieldElement())
        .map(fieldElement -> fieldElement.toArray(ByteOrder.LITTLE_ENDIAN)).toArray(byte[][]::new);
    return flatten(blob);
  }

  public static byte[] createRandomBlobs(final int count) {
    final byte[][] blobs = IntStream.range(0, count).mapToObj(__ -> createRandomBlob())
        .toArray(byte[][]::new);
    return flatten(blobs);
  }

  public static byte[] createRandomProof(final int count) {
    return CKZG4844JNI.computeAggregateKzgProof(createRandomBlobs(count), count);
  }

  public static byte[] createRandomCommitment() {
    return CKZG4844JNI.blobToKzgCommitment(createRandomBlob());
  }

  public static byte[] createRandomCommitments(final int count) {
    final byte[][] commitments = IntStream.range(0, count).mapToObj(__ -> createRandomCommitment())
        .toArray(byte[][]::new);
    return flatten(commitments);
  }

  public static byte[] createNonCanonicalBlob() {
    final byte[][] blob = IntStream.range(0, CKZG4844JNI.getFieldElementsPerBlob())
        .mapToObj(__ -> UInt256.valueOf(CKZG4844JNI.BLS_MODULUS.add(BigInteger.valueOf(42))))
        .map(greaterThanModulus -> greaterThanModulus.toArray(ByteOrder.LITTLE_ENDIAN))
        .toArray(byte[][]::new);
    return flatten(blob);
  }

  /**
   * Generated using <a
   * href="https://github.com/crate-crypto/proto-danksharding-fuzzy-test/">proto-danksharding-fuzzy-test</a>
   */
  public static List<VerifyKzgProofParameters> getVerifyKzgProofTestVectors() {
    final JsonNode jsonNode;
    try (final InputStream testVectors = readResource(
        "test-vectors/public_verify_kzg_proof.json")) {
      jsonNode = OBJECT_MAPPER.readTree(testVectors);
    } catch (final IOException ex) {
      throw new UncheckedIOException(ex);
    }
    final ArrayNode testCases = (ArrayNode) jsonNode.get("TestCases");
    final Stream.Builder<VerifyKzgProofParameters> testVectors = Stream.builder();
    testVectors.add(VerifyKzgProofParameters.ZERO);
    IntStream.range(0, jsonNode.get("NumTestCases").asInt()).mapToObj(i -> {
      final JsonNode testCase = testCases.get(i);
      final Bytes32 z = Bytes32.fromHexString(testCase.get("InputPoint").asText());
      final Bytes32 y = Bytes32.fromHexString(testCase.get("ClaimedValue").asText());
      final Bytes commitment = Bytes.fromHexString(testCase.get("Commitment").asText(),
          CKZG4844JNI.BYTES_PER_COMMITMENT);
      final Bytes proof = Bytes.fromHexString(testCase.get("Proof").asText(),
          CKZG4844JNI.BYTES_PER_PROOF);
      return new VerifyKzgProofParameters(commitment.toArray(), z.toArray(), y.toArray(),
          proof.toArray());
    }).forEach(testVectors::add);
    return testVectors.build().collect(Collectors.toList());
  }

  public static LoadTrustedSetupParameters createLoadTrustedSetupParameters(
      final String trustedSetup) {
    try (final BufferedReader reader = new BufferedReader(new FileReader(trustedSetup))) {
      final int g1Count = Integer.parseInt(reader.readLine());
      final int g2Count = Integer.parseInt(reader.readLine());

      final ByteBuffer g1 = ByteBuffer.allocate(g1Count * 48);
      final ByteBuffer g2 = ByteBuffer.allocate(g2Count * 96);

      for (int i = 0; i < g1Count; i++) {
        g1.put(Bytes.fromHexString(reader.readLine()).toArray());
      }
      for (int i = 0; i < g2Count; i++) {
        g2.put(Bytes.fromHexString(reader.readLine()).toArray());
      }

      return new LoadTrustedSetupParameters(g1.array(), g1Count, g2.array(), g2Count);
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
    return randomBLSFieldElement().toArray(ByteOrder.LITTLE_ENDIAN);
  }

  private static InputStream readResource(final String resource) {
    return Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
  }

}
