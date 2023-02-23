package ethereum.ckzg4844;

import java.util.List;
import java.util.stream.Collectors;
import org.apache.tuweni.bytes.Bytes;

public class VerifyBlobKzgProofBatchTest {
  public class Input {
    private List<String> blobs;
    private List<String> commitments;
    private List<String> proofs;

    public byte[] getBlobs() {
      byte[][] bytes =
          blobs.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new);
      return TestUtils.flatten(bytes);
    }

    public void setBlobs(List<String> blobs) {
      this.blobs = blobs;
    }

    public byte[] getCommitments() {
      byte[][] bytes =
          commitments.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new);
      return TestUtils.flatten(bytes);
    }

    public void setCommitments(List<String> commitments) {
      this.commitments = commitments;
    }

    public byte[] getProofs() {
      byte[][] bytes =
          proofs.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new);
      return TestUtils.flatten(bytes);
    }

    public void setProofs(List<String> proofs) {
      this.proofs = proofs;
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
