package ethereum.ckzg4844;

import org.apache.tuweni.bytes.Bytes;

public class VerifyBlobKzgProofTest {
  public class Input {
    private String blob;
    private String commitment;
    private String proof;

    public byte[] getBlob() {
      return Bytes.fromHexString(blob).toArray();
    }

    public void setBlob(String blob) {
      this.blob = blob;
    }

    public byte[] getCommitment() {
      return Bytes.fromHexString(commitment).toArray();
    }

    public void setCommitment(String commitment) {
      this.commitment = commitment;
    }

    public byte[] getProof() {
      return Bytes.fromHexString(proof).toArray();
    }

    public void setProof(String proof) {
      this.proof = proof;
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
