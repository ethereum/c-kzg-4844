package ethereum.ckzg4844.test_formats;

import ethereum.ckzg4844.ByteArrayTuple;
import java.util.List;
import org.apache.tuweni.bytes.Bytes;

public class ComputeKZGProofTest {
  public static class Input {
    private String blob;
    private String z;

    public byte[] getBlob() {
      return Bytes.fromHexString(blob).toArray();
    }

    public byte[] getZ() {
      return Bytes.fromHexString(z).toArray();
    }
  }

  private Input input;
  private List<String> output;

  public Input getInput() {
    return input;
  }

  public ByteArrayTuple getOutput() {
    if (output == null) {
      return null;
    }
    byte[] proof = Bytes.fromHexString(output.get(0)).toArray();
    byte[] y = Bytes.fromHexString(output.get(1)).toArray();
    return ByteArrayTuple.of(proof, y);
  }
}
