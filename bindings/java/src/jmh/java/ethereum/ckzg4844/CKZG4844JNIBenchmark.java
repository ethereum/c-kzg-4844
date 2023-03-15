package ethereum.ckzg4844;

import ethereum.ckzg4844.CKZG4844JNI.Preset;
import java.util.concurrent.TimeUnit;
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
  public static class BlobToKZGCommitmentState {
    private byte[] blob;

    @Setup(Level.Iteration)
    public void setUp() {
      blob = TestUtils.createRandomBlob();
    }
  }

  @State(Scope.Benchmark)
  public static class ComputeKZGProofState {
    private byte[] blob;
    private byte[] z;

    @Setup(Level.Iteration)
    public void setUp() {
      blob = TestUtils.createRandomBlob();
      z = TestUtils.randomBLSFieldElementBytes();
    }
  }

  @State(Scope.Benchmark)
  public static class ComputeBlobKZGProofState {
    private byte[] blob;
    private byte[] commitment;

    @Setup(Level.Iteration)
    public void setUp() {
      blob = TestUtils.createRandomBlob();
      commitment = TestUtils.createRandomCommitment();
    }
  }

  @State(Scope.Benchmark)
  public static class VerifyKZGProofState {
    private byte[] commitment;
    private byte[] z;
    private byte[] y;
    private byte[] proof;

    @Setup(Level.Iteration)
    public void setUp() {
      commitment = TestUtils.createRandomCommitments(1);
      z = TestUtils.randomBLSFieldElementBytes();
      y = TestUtils.randomBLSFieldElementBytes();
      proof = TestUtils.createRandomProofs(1);
    }
  }

  @State(Scope.Benchmark)
  public static class VerifyBlobKZGProofState {
    private byte[] blob;
    private byte[] commitment;
    private byte[] proof;

    @Setup(Level.Iteration)
    public void setUp() {
      blob = TestUtils.createRandomBlobs(1);
      commitment = TestUtils.createRandomCommitments(1);
      proof = TestUtils.createRandomProofs(1);
    }
  }

  @State(Scope.Benchmark)
  public static class VerifyBlobKZGProofBatchState {
    @Param({"1", "4", "8", "16", "32", "64"})
    private int count;

    private byte[] blobs;
    private byte[] commitments;
    private byte[] proofs;

    @Setup(Level.Iteration)
    public void setUp() {
      blobs = TestUtils.createRandomBlobs(count);
      commitments = TestUtils.createRandomCommitments(count);
      proofs = TestUtils.createRandomProofs(count);
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
  public byte[] blobToKZGCommitment(final BlobToKZGCommitmentState state) {
    return CKZG4844JNI.blobToKZGCommitment(state.blob);
  }

  @Benchmark
  public ByteArrayTuple computeKZGProof(final ComputeKZGProofState state) {
    return CKZG4844JNI.computeKZGProof(state.blob, state.z);
  }

  @Benchmark
  public byte[] computeBlobKZGProof(final ComputeBlobKZGProofState state) {
    return CKZG4844JNI.computeBlobKZGProof(state.blob, state.commitment);
  }

  @Benchmark
  public boolean verifyKZGProof(final VerifyKZGProofState state) {
    return CKZG4844JNI.verifyKZGProof(state.commitment, state.z, state.y, state.proof);
  }

  @Benchmark
  public boolean verifyBlobKZGProof(final VerifyBlobKZGProofState state) {
    return CKZG4844JNI.verifyBlobKZGProof(state.blob, state.commitment, state.proof);
  }

  @Benchmark
  public boolean verifyBlobKZGProofBatch(final VerifyBlobKZGProofBatchState state) {
    return CKZG4844JNI.verifyBlobKZGProofBatch(
        state.blobs, state.commitments, state.proofs, state.count);
  }
}
