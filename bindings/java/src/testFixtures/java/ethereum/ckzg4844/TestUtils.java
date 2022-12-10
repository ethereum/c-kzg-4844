package ethereum.ckzg4844;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.IntStream;
import org.apache.tuweni.units.bigints.UInt256;

public class TestUtils {

  private static final Random RANDOM = new Random();

  public static byte[] flatten(final byte[]... bytes) {
    final int capacity = Arrays.stream(bytes).mapToInt(b -> b.length).sum();
    final ByteBuffer buffer = ByteBuffer.allocate(capacity);
    Arrays.stream(bytes).forEach(buffer::put);
    return buffer.array();
  }

  public static byte[] createRandomBlob() {
    final byte[][] blob = IntStream.range(0, CKZG4844JNI.getFieldElementsPerBlob())
        .mapToObj(__ -> randomBlsFieldElement())
        .map(blsFieldElement -> blsFieldElement.toArray(ByteOrder.LITTLE_ENDIAN))
        .toArray(byte[][]::new);
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

  private static UInt256 randomBlsFieldElement() {
    final BigInteger attempt = new BigInteger(CKZG4844JNI.BLS_MODULUS.bitLength(), RANDOM);
    if (attempt.compareTo(CKZG4844JNI.BLS_MODULUS) < 0) {
      return UInt256.valueOf(attempt);
    }
    return randomBlsFieldElement();
  }

}
