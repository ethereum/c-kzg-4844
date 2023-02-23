package ethereum.ckzg4844;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tuweni.bytes.Bytes;

public class VerifyKzgProofTest {
  public class Input {
    private byte[] commitment;

    @JsonProperty("input_point")
    private byte[] inputPoint;

    @JsonProperty("claimed_value")
    private byte[] claimedValue;

    private byte[] proof;

    public byte[] getCommitment() {
      return commitment;
    }

    public void setCommitment(String commitment) {
      this.commitment = Bytes.fromHexString(commitment).toArray();
    }

    public byte[] getInputPoint() {
      return inputPoint;
    }

    public void setInputPoint(String inputPoint) {
      this.inputPoint = Bytes.fromHexString(inputPoint).toArray();
    }

    public byte[] getClaimedValue() {
      return claimedValue;
    }

    public void setClaimedValue(String claimedValue) {
      this.claimedValue = Bytes.fromHexString(claimedValue).toArray();
    }

    public byte[] getProof() {
      return proof;
    }

    public void setProof(String proof) {
      this.proof = Bytes.fromHexString(proof).toArray();
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
