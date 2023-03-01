package ethereum.ckzg4844;

import org.apache.tuweni.bytes.Bytes;

public class ComputeKzgProofTest {
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
  private String output;

  public Input getInput() {
    return input;
  }

  public byte[] getOutput() {
    if (output == null) {
      return null;
    }
    return Bytes.fromHexString(output).toArray();
  }
}
