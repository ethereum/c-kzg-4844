package ethereum.ckzg4844;

public class VerifyBlobKzgProofBatchTest {
  public static class Input {
    public byte[] blobs;
    public byte[] commitments;
    public byte[] proofs;
  }

  public static class Output {
    public Boolean valid;
  }

  public Input input;
  public Output output;
}
