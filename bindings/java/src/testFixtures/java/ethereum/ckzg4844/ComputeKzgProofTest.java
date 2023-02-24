package ethereum.ckzg4844;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ComputeKzgProofTest {
  public static class Input {
    public byte[] blob;

    @JsonProperty("input_point")
    public byte[] inputPoint;
  }

  public static class Output {
    public byte[] proof;
  }

  public Input input;
  public Output output;
}
