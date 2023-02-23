package ethereum.ckzg4844;

import org.apache.tuweni.bytes.Bytes;

public class BlobToKzgCommitmentTest {
  public class Input {
    private String blob;

    public byte[] getBlob() {
      return Bytes.fromHexString(blob).toArray();
    }

    public void setBlob(String blob) {
      this.blob = blob;
    }
  }

  public class Output {
    private String commitment;

    public byte[] getCommitment() {
      if (commitment == null) {
        return null;
      }
      return Bytes.fromHexString(commitment).toArray();
    }

    public void setCommitment(String commitment) {
      this.commitment = commitment;
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
