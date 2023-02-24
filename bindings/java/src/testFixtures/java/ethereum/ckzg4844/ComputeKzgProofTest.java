package ethereum.ckzg4844;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tuweni.bytes.Bytes;

public class ComputeKzgProofTest {
  public static class Input {
    private String blob;

    @JsonProperty("input_point")
    private String inputPoint;

    public byte[] getBlob() {
      return Bytes.fromHexString(blob).toArray();
    }

    public byte[] getInputPoint() {
      return Bytes.fromHexString(inputPoint).toArray();
    }
  }

  public static class Output {
    private String proof;

    public byte[] getProof() {
      if (proof == null) {
        return null;
      }
      return Bytes.fromHexString(proof).toArray();
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
