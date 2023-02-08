package ethereum.ckzg4844;

import ethereum.ckzg4844.CKZG4844JNI.Preset;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;

@BenchmarkMode(Mode.AverageTime)
@Fork(value = 1)
@Warmup(iterations = 1, time = 1000, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 5, time = 1000, timeUnit = TimeUnit.MILLISECONDS)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
public class CKZG4844JNIBenchmark {

  static {
    CKZG4844JNI.loadNativeLibrary(Preset.MAINNET);
  }

  @State(Scope.Benchmark)
  public static class BlobToKzgCommitmentState {

    private byte[] blob;

    @Setup(Level.Iteration)
    public void setUp() {
      blob = TestUtils.createRandomBlob();
    }
  }

  @State(Scope.Benchmark)
  public static class ComputeKzgProofState {

    private byte[] blob;
    private byte[] z;

    @Setup(Level.Iteration)
    public void setUp() {
      blob = TestUtils.createRandomBlob();
      z = TestUtils.randomBLSFieldElementBytes();
    }
  }

  @State(Scope.Benchmark)
  public static class ComputeAndVerifyState {

    @Param({"1", "4", "8", "16"})
    private int count;

    private byte[] blobs;
    private byte[] commitments;
    private byte[] proof;

    @Setup(Level.Iteration)
    public void setUp() {
      final byte[][] blobs = new byte[count][];
      final byte[][] commitments = new byte[count][];
      IntStream.range(0, count).forEach(i -> {
        blobs[i] = TestUtils.createRandomBlob();
        commitments[i] = CKZG4844JNI.blobToKzgCommitment(blobs[i]);
      });
      this.blobs = TestUtils.flatten(blobs);
      this.commitments = TestUtils.flatten(commitments);
      proof = CKZG4844JNI.computeAggregateKzgProof(TestUtils.flatten(blobs), count);
    }
  }

  @State(Scope.Benchmark)
  public static class VerifyKzgProofState {

    private byte[] commitment;
    private byte[] z;
    private byte[] y;
    private byte[] proof;

    @Setup
    public void setUp() {
      final VerifyKzgProofParameters parameters = TestUtils.getVerifyKzgProofTestVectors().get(2);
      commitment = parameters.getCommitment();
      z = parameters.getZ();
      y = parameters.getY();
      proof = parameters.getProof();
    }
  }

  @Setup
  public void setUp() {
    CKZG4844JNI.loadTrustedSetup("../../src/trusted_setup.txt");
  }

  @TearDown
  public void tearDown() {
    CKZG4844JNI.freeTrustedSetup();
  }

  @Benchmark
  public byte[] blobToKzgCommitment(final BlobToKzgCommitmentState state) {
    return CKZG4844JNI.blobToKzgCommitment(state.blob);
  }

  @Benchmark
  public byte[] computeKzgProof(final ComputeKzgProofState state) {
    return CKZG4844JNI.computeKzgProof(state.blob, state.z);
  }

  @Benchmark
  public byte[] computeAggregateKzgProof(final ComputeAndVerifyState state) {
    return CKZG4844JNI.computeAggregateKzgProof(state.blobs, state.count);
  }

  @Benchmark
  public boolean verifyAggregateKzgProof(final ComputeAndVerifyState state) {
    return CKZG4844JNI.verifyAggregateKzgProof(state.blobs, state.commitments, state.count,
        state.proof);
  }

  @Benchmark
  @OutputTimeUnit(TimeUnit.NANOSECONDS)
  public boolean verifyKzgProof(final VerifyKzgProofState state) {
    return CKZG4844JNI.verifyKzgProof(state.commitment, state.z, state.y, state.proof);
  }

}