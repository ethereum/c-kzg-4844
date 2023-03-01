package ethereum.ckzg4844;

import org.apache.tuweni.bytes.Bytes;

public class VerifyBlobKzgProofTest {
  public static class Input {
    public String blob;
    public String commitment;
    public String proof;

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

  public Input input;
  public Boolean output;

  public Input getInput() {
    return input;
  }

  public Boolean getOutput() {
    return output;
  }
}
