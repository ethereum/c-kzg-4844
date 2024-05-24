package ethereum.ckzg4844;

public class LoadTrustedSetupParameters {

  private final byte[] g1Monomial;
  private final byte[] g1Lagrange;
  private final long g1Count;
  private final byte[] g2Monomial;
  private final long g2Count;

  public LoadTrustedSetupParameters(
      final byte[] g1Monomial,
      final byte[] g1Lagrange,
      final long g1Count,
      final byte[] g2Monomial,
      final long g2Count) {
    this.g1Monomial = g1Monomial;
    this.g1Lagrange = g1Lagrange;
    this.g1Count = g1Count;
    this.g2Monomial = g2Monomial;
    this.g2Count = g2Count;
  }

  public byte[] getG1Monomial() {
    return g1Monomial;
  }

  public byte[] getG1Lagrange() {
    return g1Lagrange;
  }

  public long getG1Count() {
    return g1Count;
  }

  public byte[] getG2Monomial() {
    return g2Monomial;
  }

  public long getG2Count() {
    return g2Count;
  }
}
