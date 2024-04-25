package ethereum.ckzg4844.test_formats;

import com.fasterxml.jackson.annotation.JsonProperty;
import ethereum.ckzg4844.TestUtils;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.tuweni.bytes.Bytes;

public class RecoverAllCellsTest {
  public static class Input {
    @JsonProperty("cell_ids")
    private List<Long> cellIds;

    private List<String> cells;

    public long[] getCellIds() {
      return cellIds.stream().mapToLong(Long::longValue).toArray();
    }

    public byte[] getCells() {
      return TestUtils.flatten(
          cells.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArrayUnsafe)
              .collect(Collectors.toList())
              .toArray(byte[][]::new));
    }
  }

  private Input input;
  private List<String> output;

  public Input getInput() {
    return input;
  }

  public byte[] getOutput() {
    if (output == null) {
      return null;
    }
    return TestUtils.flatten(
        output.stream()
            .map(Bytes::fromHexString)
            .map(Bytes::toArrayUnsafe)
            .collect(Collectors.toList())
            .toArray(byte[][]::new));
  }
}
