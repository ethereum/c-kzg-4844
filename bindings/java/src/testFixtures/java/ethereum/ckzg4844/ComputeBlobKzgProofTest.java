package ethereum.ckzg4844;

import org.apache.tuweni.bytes.Bytes;

public class ComputeBlobKzgProofTest {
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
    private String proof;

    public byte[] getProof() {
      if (proof == null) {
        return null;
      }
      return Bytes.fromHexString(proof).toArray();
    }

    public void setProof(String proof) {
      this.proof = proof;
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
