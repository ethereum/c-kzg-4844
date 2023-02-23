package ethereum.ckzg4844;

import org.apache.tuweni.bytes.Bytes;

public class BlobToKzgCommitmentTest {
  public class Input {
    private byte[] blob;

    public byte[] getBlob() {
      return blob;
    }

    public void setBlob(String blob) {
      this.blob = Bytes.fromHexString(blob).toArray();
    }
  }

  public class Output {
    private byte[] commitment;

    public byte[] getCommitment() {
      return commitment;
    }

    public void setCommitment(String commitment) {
      this.commitment = Bytes.fromHexString(commitment).toArray();
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
