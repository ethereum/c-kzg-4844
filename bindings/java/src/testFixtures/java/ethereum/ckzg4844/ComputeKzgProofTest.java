package ethereum.ckzg4844;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tuweni.bytes.Bytes;

public class ComputeKzgProofTest {
  public class Input {
    private byte[] blob;

    @JsonProperty("input_point")
    private byte[] inputPoint;

    public byte[] getBlob() {
      return blob;
    }

    public void setBlob(String blob) {
      this.blob = Bytes.fromHexString(blob).toArray();
    }

    public byte[] getInputPoint() {
      return inputPoint;
    }

    public void setInputPoint(String inputPoint) {
      this.inputPoint = Bytes.fromHexString(inputPoint).toArray();
    }
  }

  public class Output {
    private byte[] proof;

    public byte[] getProof() {
      return proof;
    }

    public void setProof(String proof) {
      this.proof = Bytes.fromHexString(proof).toArray();
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
