package ethereum.ckzg4844;

import com.fasterxml.jackson.annotation.JsonProperty;

public class VerifyKzgProofTest {
  public static class Input {
    public byte[] commitment;

    @JsonProperty("input_point")
    public byte[] inputPoint;

    @JsonProperty("claimed_value")
    public byte[] claimedValue;

    public byte[] proof;
  }

  public static class Output {
    public Boolean valid;
  }

  public Input input;
  public Output output;
}
