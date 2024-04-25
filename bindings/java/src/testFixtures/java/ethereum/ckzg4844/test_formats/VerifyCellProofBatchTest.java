package ethereum.ckzg4844.test_formats;

import com.fasterxml.jackson.annotation.JsonProperty;
import ethereum.ckzg4844.TestUtils;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.tuweni.bytes.Bytes;

public class VerifyCellProofBatchTest {
  public static class Input {
    @JsonProperty("row_commitments")
    private List<String> rowCommitments;

    @JsonProperty("row_indices")
    private List<Long> rowIndices;

    @JsonProperty("column_indices")
    private List<Long> columnIndices;

    private List<String> cells;
    private List<String> proofs;

    public byte[] getRowCommitments() {
      return TestUtils.flatten(
          rowCommitments.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new));
    }

    public long[] getRowIndices() {
      return rowIndices.stream().mapToLong(Long::longValue).toArray();
    }

    public long[] getColumnIndices() {
      return columnIndices.stream().mapToLong(Long::longValue).toArray();
    }

    public byte[] getCells() {
      return TestUtils.flatten(
          cells.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArrayUnsafe)
              .collect(Collectors.toList())
              .toArray(byte[][]::new));
    }

    public byte[] getProofs() {
      return TestUtils.flatten(
          proofs.stream()
              .map(Bytes::fromHexString)
              .map(Bytes::toArray)
              .collect(Collectors.toList())
              .toArray(byte[][]::new));
    }
  }

  private Input input;
  private Boolean output;

  public Input getInput() {
    return input;
  }

  public Boolean getOutput() {
    return output;
  }
}
