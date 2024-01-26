package ethereum.ckzg4844;

import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_CELL;
import static ethereum.ckzg4844.CKZG4844JNI.BYTES_PER_PROOF;
import static ethereum.ckzg4844.CKZG4844JNI.CELLS_PER_BLOB;

import java.util.Arrays;

public class CellsAndProofs {
  private final byte[] cells;
  private final byte[] proofs;

  public CellsAndProofs(final byte[] cells, final byte[] proofs) {
    this.cells = cells;
    this.proofs = proofs;
  }

  public byte[] getCells() {
    return cells;
  }

  public byte[] getProofs() {
    return proofs;
  }

  public static CellsAndProofs of(final byte[] cells, final byte[] proofs) {
    return new CellsAndProofs(cells, proofs);
  }

  public byte[] toBytes() {
    final byte[] bytes = new byte[BYTES_PER_CELL * (BYTES_PER_CELL + BYTES_PER_PROOF)];
    int offset = 0;
    System.arraycopy(cells, 0, bytes, offset, CELLS_PER_BLOB * BYTES_PER_CELL);
    offset += CELLS_PER_BLOB * BYTES_PER_CELL;
    System.arraycopy(proofs, 0, bytes, offset, CELLS_PER_BLOB * BYTES_PER_PROOF);
    return bytes;
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(cells);
    result = 31 * result + Arrays.hashCode(proofs);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null || getClass() != obj.getClass()) return false;

    CellsAndProofs other = (CellsAndProofs) obj;
    return Arrays.equals(cells, other.cells) && Arrays.equals(proofs, other.proofs);
  }
}
