package ethereum.ckzg4844.test_formats;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tuweni.bytes.Bytes;

public class VerifyCellProofTest {
  public static class Input {
    private String commitment;

    @JsonProperty("cell_id")
    private Long cellId;

    private String cell;
    private String proof;

    public byte[] getCommitment() {
      return Bytes.fromHexString(commitment).toArray();
    }

    public Long getCellId() {
      return cellId;
    }

    public byte[] getCell() {
      return Bytes.fromHexString(cell).toArrayUnsafe();
    }

    public byte[] getProof() {
      return Bytes.fromHexString(proof).toArray();
    }
  }

  private Input input;
  private Boolean output;

  public Input getInput() {
    return input;
  }

  public Boolean getOutput() {
    return output;
  }
}
