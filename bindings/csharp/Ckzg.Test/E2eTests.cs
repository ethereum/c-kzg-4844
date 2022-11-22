using NUnit.Framework;

namespace Ckzg.Test;

[TestFixture]
public class BasicKzgTests
{
    [TestCase]
    public unsafe void Test_Computes_And_Verifies()
    {
        IntPtr ts = Ckzg.LoadTrustedSetup("trusted_setup.txt");
        Assert.That((ulong)ts, Is.Not.EqualTo((ulong)0));
        byte[] blob = Enumerable.Range(0, 4096 * 32).Select(x => (byte)(x % 256)).ToArray();

        byte[] proof = new byte[48];
        byte[] commitment = new byte[48];
        fixed (byte* commitmentPtr = commitment, blobPtr = blob, proofPtr = proof)
        {
            Ckzg.ComputeAggregatedKzgProof(proofPtr, blobPtr, 1, ts);
            Ckzg.BlobToKzgCommitment(commitmentPtr, blobPtr, ts);
            int result = Ckzg.VerifyAggregatedKzgProof(blobPtr, commitmentPtr, 1, proofPtr, ts);
            Assert.That(result, Is.EqualTo(0));
            Ckzg.FreeTrustedSetup(ts);
        }
    }

    [TestCase]
    public unsafe void Test_PointEvaluationPrecompile_Verifies()
    {
        IntPtr ts = Ckzg.LoadTrustedSetup("trusted_setup.txt");
        Assert.That((ulong)ts, Is.Not.EqualTo((ulong)0));
        byte[] commitment = new byte[48];
        commitment[0] = 0xc0;
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        byte[] proof = new byte[48];
        proof[0] = 0xc0;

        fixed (byte* commitmentPtr = commitment, xPtr = x, yPtr = y, proofPtr = proof)
        {
            int result = Ckzg.VerifyKzgProof(commitmentPtr, xPtr, yPtr, proofPtr, ts);
            Ckzg.FreeTrustedSetup(ts);
            Assert.That(result, Is.EqualTo(0));
        }
    }
}