package ethereum.ckzg4844;

import java.util.List;
import java.util.stream.Collectors;
import org.apache.tuweni.bytes.Bytes;

public class VerifyBlobKzgProofBatchTest {
  public static class Input {
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

    public byte[] getCommitments() {
      byte[][] bytes =
          commitments.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new);
      return TestUtils.flatten(bytes);
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
