package ethereum.ckzg4844;

import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_FIELD_ELEMENT;
import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_PROOF;
import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_SAMPLE;
import static ethereum.ckzg4844.CKZG4844JNI.SAMPLES_PER_BLOB;
import static ethereum.ckzg4844.CKZG4844JNI.SAMPLE_SIZE;

public class Sample {
  private final byte[] data;
  private final byte[] proof;
  private final int rowIndex;
  private final int columnIndex;

  public Sample(final byte[] data, final byte[] proof, final int rowIndex, final int columnIndex) {
    this.data = data;
    this.proof = proof;
    this.rowIndex = rowIndex;
    this.columnIndex = columnIndex;
  }

  public byte[] getData() {
    return data;
  }

  public byte[] getProof() {
    return proof;
  }

  public int getRowIndex() {
    return rowIndex;
  }

  public int getColumnIndex() {
    return columnIndex;
  }

  public static Sample[] of(final byte[] bytes) {
    final Sample[] samples = new Sample[SAMPLES_PER_BLOB];
    final int dataLength = SAMPLE_SIZE * BYTES_PER_FIELD_ELEMENT;
    final int proofLength = BYTES_PER_PROOF;
    final int indexLength = 4;

    for (int i = 0; i < SAMPLES_PER_BLOB; i++) {
      int offset = i * BYTES_PER_SAMPLE;

      final byte[] data = new byte[dataLength];
      System.arraycopy(bytes, offset, data, 0, dataLength);
      offset += dataLength;

      final byte[] proof = new byte[proofLength];
      System.arraycopy(bytes, offset, proof, 0, proofLength);
      offset += proofLength;

      final byte[] rowIndexBytes = new byte[indexLength];
      System.arraycopy(bytes, offset, rowIndexBytes, 0, indexLength);
      final int rowIndex = bytesToInt(rowIndexBytes);

      samples[i] = new Sample(data, proof, rowIndex, i);
    }

    return samples;
  }

  public byte[] toBytes() {
    int offset = 0;
    final byte[] bytes = new byte[BYTES_PER_SAMPLE];
    final int dataLength = SAMPLE_SIZE * BYTES_PER_FIELD_ELEMENT;
    final int proofLength = BYTES_PER_PROOF;
    final int indexLength = 4;

    System.arraycopy(data, 0, bytes, offset, dataLength);
    offset += dataLength;

    System.arraycopy(proof, 0, bytes, offset, proofLength);
    offset += proofLength;

    System.arraycopy(intToBytes(rowIndex), 0, bytes, offset, indexLength);
    offset += indexLength;

    System.arraycopy(intToBytes(columnIndex), 0, bytes, offset, indexLength);

    return bytes;
  }

  private static int bytesToInt(final byte[] bytes) {
    return ((bytes[0] & 0xFF) & 0xFF)
        | ((bytes[1] & 0xFF) << 8)
        | ((bytes[2] & 0xFF) << 16)
        | ((bytes[3] & 0xFF) << 24);
  }

  private static byte[] intToBytes(final int value) {
    byte[] bytes = new byte[4];
    bytes[0] = (byte) (value & 0xFF);
    bytes[1] = (byte) (value >> 8 & 0xFF);
    bytes[2] = (byte) (value >> 16 & 0xFF);
    bytes[3] = (byte) (value >> 24 & 0xFF);
    return bytes;
  }
}
