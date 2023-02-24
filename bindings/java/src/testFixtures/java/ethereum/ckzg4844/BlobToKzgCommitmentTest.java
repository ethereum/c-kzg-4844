package ethereum.ckzg4844;

public class BlobToKzgCommitmentTest {
  public static class Input {
    public byte[] blob;
  }

  public static class Output {
    public byte[] commitment;
  }

  public Input input;
  public Output output;
}
