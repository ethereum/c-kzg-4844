package ethereum.ckzg4844;

public class VerifyBlobKzgProofTest {
  public static class Input {
    public byte[] blob;
    public byte[] commitment;
    public byte[] proof;
  }

  public static class Output {
    public Boolean valid;
  }

  public Input input;
  public Output output;
}
