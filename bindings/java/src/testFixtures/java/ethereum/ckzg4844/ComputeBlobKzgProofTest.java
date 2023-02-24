package ethereum.ckzg4844;

import org.apache.tuweni.bytes.Bytes;

public class ComputeBlobKzgProofTest {
  public static class Input {
    private String blob;

    public byte[] getBlob() {
      return Bytes.fromHexString(blob).toArray();
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
