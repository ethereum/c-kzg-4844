package ethereum.ckzg4844;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tuweni.bytes.Bytes;

public class VerifyKzgProofTest {
  public static class Input {
    private String commitment;

    @JsonProperty("input_point")
    private String inputPoint;

    @JsonProperty("claimed_value")
    private String claimedValue;

    private String proof;

    public byte[] getCommitment() {
      return Bytes.fromHexString(commitment).toArray();
    }

    public byte[] getInputPoint() {
      return Bytes.fromHexString(inputPoint).toArray();
    }

    public byte[] getClaimedValue() {
      return Bytes.fromHexString(claimedValue).toArray();
    }

    public byte[] getProof() {
      return Bytes.fromHexString(proof).toArray();
    }
  }

  public static class Output {
    private Boolean valid;

    public Boolean getValid() {
      return valid;
    }
  }

  private Input input;
  private Output output;

  public Input getInput() {
    return input;
  }

  public Output getOutput() {
    return output;
  }
}
