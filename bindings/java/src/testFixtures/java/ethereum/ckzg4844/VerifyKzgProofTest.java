package ethereum.ckzg4844;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tuweni.bytes.Bytes;

public class VerifyKzgProofTest {
  public class Input {
    private String commitment;

    @JsonProperty("input_point")
    private String inputPoint;

    @JsonProperty("claimed_value")
    private String claimedValue;

    private String proof;

    public byte[] getCommitment() {
      return Bytes.fromHexString(commitment).toArray();
    }

    public void setCommitment(String commitment) {
      this.commitment = commitment;
    }

    public byte[] getInputPoint() {
      return Bytes.fromHexString(inputPoint).toArray();
    }

    public void setInputPoint(String inputPoint) {
      this.inputPoint = inputPoint;
    }

    public byte[] getClaimedValue() {
      return Bytes.fromHexString(claimedValue).toArray();
    }

    public void setClaimedValue(String claimedValue) {
      this.claimedValue = claimedValue;
    }

    public byte[] getProof() {
      return Bytes.fromHexString(proof).toArray();
    }

    public void setProof(String proof) {
      this.proof = proof;
    }
  }

  public class Output {
    private Boolean valid;

    public Boolean getValid() {
      return valid;
    }

    public void setValid(Boolean valid) {
      this.valid = valid;
    }
  }

  private Input input;
  private Output output;

  public Input getInput() {
    return input;
  }

  public void setInput(Input input) {
    this.input = input;
  }

  public Output getOutput() {
    return output;
  }

  public void setOutput() {
    this.output = output;
  }
}
