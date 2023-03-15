package ethereum.ckzg4844;

/** A tuple holding 2 byte arrays. */
public class ByteArrayTuple {
  private final byte[] first;
  private final byte[] second;

  public ByteArrayTuple(byte[] first, byte[] second) {
    this.first = first;
    this.second = second;
  }

  public byte[] getFirst() {
    return first;
  }

  public byte[] getSecond() {
    return second;
  }

  public static ByteArrayTuple of(byte[] first, byte[] second) {
    return new ByteArrayTuple(first, second);
  }
}
