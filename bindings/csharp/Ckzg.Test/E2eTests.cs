using NUnit.Framework;

namespace Ckzg.Test;

[TestFixture]
public class BasicKzgTests
{
    private IntPtr _ts;

    [SetUp]
    public void Setup()
    {
        _ts = Ckzg.LoadTrustedSetup("trusted_setup.txt");
        Assert.That(_ts, Is.Not.EqualTo(IntPtr.Zero));
    }

    [TestCase(0xff, 1, -1)]
    [TestCase(0x73, 1, -1)]
    [TestCase(0x72, 0, 0)]
    [TestCase(0x00, 0, 0)]
    public unsafe void Test_Computes_And_Verifies(byte highByteValue, int expectedProofComputed, int expectedProofVerified)
    {
        byte[] blob = Enumerable.Range(0, 4096 * 32).Select(x => x % 32 == 31 ? highByteValue : (byte)(x % 256)).ToArray();

        byte[] proof = new byte[48];
        byte[] commitment = new byte[48];
        fixed (byte* commitmentPtr = commitment, blobPtr = blob, proofPtr = proof)
        {
            int proofComputed = Ckzg.ComputeAggregatedKzgProof(proofPtr, blobPtr, 1, _ts);
            Assert.That(proofComputed, Is.EqualTo(expectedProofComputed));

            Ckzg.BlobToKzgCommitment(commitmentPtr, blobPtr, _ts);
            int proofVerified = Ckzg.VerifyAggregatedKzgProof(blobPtr, commitmentPtr, 1, proofPtr, _ts);
            Assert.That(proofVerified, Is.EqualTo(expectedProofVerified));

            Ckzg.FreeTrustedSetup(_ts);
        }
    }

    [TestCase]
    public unsafe void Test_PointEvaluationPrecompile_Verifies()
    {
        byte[] commitment = new byte[48];
        commitment[0] = 0xc0;
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        byte[] proof = new byte[48];
        proof[0] = 0xc0;

        fixed (byte* commitmentPtr = commitment, xPtr = x, yPtr = y, proofPtr = proof)
        {
            int result = Ckzg.VerifyKzgProof(commitmentPtr, xPtr, yPtr, proofPtr, _ts);
            Ckzg.FreeTrustedSetup(_ts);
            Assert.That(result, Is.EqualTo(0));
        }
    }
}