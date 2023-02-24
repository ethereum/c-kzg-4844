package ethereum.ckzg4844;

import org.apache.tuweni.bytes.Bytes;

public class VerifyBlobKzgProofTest {
  public static class Input {
    private String blob;
    private String commitment;
    private String proof;

    public byte[] getBlob() {
      return Bytes.fromHexString(blob).toArray();
    }

    public byte[] getCommitment() {
      return Bytes.fromHexString(commitment).toArray();
    }

    public byte[] getProof() {
      return Bytes.fromHexString(proof).toArray();
    }
  }

  public static class Output {
    private Boolean valid;

    public Boolean getValid() {
      return valid;
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
