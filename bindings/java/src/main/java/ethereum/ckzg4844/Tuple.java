package ethereum.ckzg4844;

/** A tuple holding 2 byte arrays. */
public class Tuple {
  private final byte[] first;
  private final byte[] second;

  public Tuple(byte[] first, byte[] second) {
    this.first = first;
    this.second = second;
  }

  public byte[] getFirst() {
    return first;
  }

  public byte[] getSecond() {
    return second;
  }

  public static Tuple of(byte[] first, byte[] second) {
    return new Tuple(first, second);
  }
}
