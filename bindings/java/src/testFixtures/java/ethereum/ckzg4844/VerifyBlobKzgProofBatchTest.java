package ethereum.ckzg4844;

import java.util.List;
import java.util.stream.Collectors;
import org.apache.tuweni.bytes.Bytes;

public class VerifyBlobKzgProofBatchTest {
  public class Input {
    private byte[] blobs;
    private byte[] commitments;
    private byte[] proofs;

    public byte[] getBlobs() {
      return blobs;
    }

    public void setBlobs(List<String> blobs) {
      byte[][] bytes =
          blobs.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new);
      this.blobs = TestUtils.flatten(bytes);
    }

    public byte[] getCommitments() {
      return commitments;
    }

    public void setCommitments(List<String> commitments) {
      byte[][] bytes =
          commitments.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new);
      this.commitments = TestUtils.flatten(bytes);
    }

    public byte[] getProofs() {
      return proofs;
    }

    public void setProofs(List<String> proofs) {
      byte[][] bytes =
          proofs.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new);
      this.proofs = TestUtils.flatten(bytes);
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
