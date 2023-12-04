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

  public Sample(byte[] data, byte[] proof, int rowIndex, int columnIndex) {
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

  public static Sample[] of(byte[] samples_bytes) {
    Sample[] samples = new Sample[SAMPLES_PER_BLOB];

    for (int i = 0; i < SAMPLES_PER_BLOB; i++) {
      int offset = i * BYTES_PER_SAMPLE;

      int sample_length = SAMPLE_SIZE * BYTES_PER_FIELD_ELEMENT;
      byte[] sample_chunk = new byte[sample_length];
      System.arraycopy(samples_bytes, offset, sample_chunk, 0, sample_length);
      offset += sample_length;

      int proof_length = BYTES_PER_PROOF;
      byte[] proof_chunk = new byte[proof_length];
      System.arraycopy(samples_bytes, offset, proof_chunk, 0, proof_length);
      offset += proof_length;

      int index_length = 4;
      byte[] row_index_chunk = new byte[index_length];
      System.arraycopy(samples_bytes, offset, row_index_chunk, 0, index_length);
      int rowIndex =
          ((row_index_chunk[0] & 0xFF) & 0xFF)
              | ((row_index_chunk[1] & 0xFF) << 8)
              | ((row_index_chunk[2] & 0xFF) << 16)
              | ((row_index_chunk[3] & 0xFF) << 24);

      samples[i] = new Sample(sample_chunk, proof_chunk, rowIndex, i);
    }

    return samples;
  }

  public byte[] toBytes() {
    byte[] bytes = new byte[BYTES_PER_SAMPLE];

    int offset = 0;

    int dataLength = SAMPLE_SIZE * BYTES_PER_FIELD_ELEMENT;
    System.arraycopy(data, 0, bytes, offset, dataLength);
    offset += dataLength;

    int proofLength = BYTES_PER_PROOF;
    System.arraycopy(proof, 0, bytes, offset, proofLength);
    offset += proofLength;

    int indexLength = 4;
    byte[] rowIndexBytes = new byte[4];
    rowIndexBytes[0] = (byte) (rowIndex & 0xFF);
    rowIndexBytes[1] = (byte) (rowIndex >> 8 & 0xFF);
    rowIndexBytes[2] = (byte) (rowIndex >> 16 & 0xFF);
    rowIndexBytes[3] = (byte) (rowIndex >> 24 & 0xFF);
    System.arraycopy(rowIndexBytes, 0, bytes, offset, indexLength);
    offset += indexLength;

    byte[] colIndexBytes = new byte[4];
    colIndexBytes[0] = (byte) (columnIndex & 0xFF);
    colIndexBytes[1] = (byte) (columnIndex >> 8 & 0xFF);
    colIndexBytes[2] = (byte) (columnIndex >> 16 & 0xFF);
    colIndexBytes[3] = (byte) (columnIndex >> 24 & 0xFF);
    System.arraycopy(colIndexBytes, 0, bytes, offset, indexLength);

    return bytes;
  }
}
