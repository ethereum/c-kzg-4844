package ethereum.ckzg4844;

import org.apache.tuweni.bytes.Bytes;

public class VerifyBlobKzgProofTest {
  public class Input {
    private byte[] blob;
    private byte[] commitment;
    private byte[] proof;

    public byte[] getBlob() {
      return blob;
    }

    public void setBlob(String blob) {
      this.blob = Bytes.fromHexString(blob).toArray();
    }

    public byte[] getCommitment() {
      return commitment;
    }

    public void setCommitment(String commitment) {
      this.commitment = Bytes.fromHexString(commitment).toArray();
    }

    public byte[] getProof() {
      return proof;
    }

    public void setProof(String proof) {
      this.proof = Bytes.fromHexString(proof).toArray();
    }
  }

  public class Output {
    private Boolean valid;

    public Boolean getValid() {
      return valid;
    }

    public void setValid(Boolean valid) {
      this.valid = valid;
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
