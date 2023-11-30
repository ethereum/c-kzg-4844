package ethereum.ckzg4844;

import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_FIELD_ELEMENT;
import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_PROOF;
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

  public static Sample[] of(byte[] data, byte[] proofs, int rowIndex) {
    Sample[] samples = new Sample[SAMPLES_PER_BLOB];

    for (int i = 0; i < SAMPLES_PER_BLOB; i++) {
      /* Get the sample chunk */
      int sample_length = SAMPLE_SIZE * BYTES_PER_FIELD_ELEMENT;
      byte[] sample_chunk = new byte[sample_length];
      System.arraycopy(data, i * sample_length, sample_chunk, 0, sample_length);

      /* Get the proof chunk */
      int proof_length = BYTES_PER_PROOF;
      byte[] proof_chunk = new byte[proof_length];
      System.arraycopy(proofs, i * proof_length, proof_chunk, 0, proof_length);

      /* Create the sample */
      samples[i] = new Sample(sample_chunk, proof_chunk, rowIndex, i);
    }

    return samples;
  }
}
