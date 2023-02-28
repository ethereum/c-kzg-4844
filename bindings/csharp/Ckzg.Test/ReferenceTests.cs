using NUnit.Framework;
using YamlDotNet.Serialization;
using Microsoft.Extensions.FileSystemGlobbing;

namespace Ckzg.Test;

[TestFixture]
public class BasicKzgTests
{
    private IntPtr ts;

    const string TestDir = "../../../../../../tests";
    string BlobToKZGCommitmentTests = Path.Join(TestDir, "blob_to_kzg_commitment");
    string ComputeKzgProofTests = Path.Join(TestDir, "compute_kzg_proof");
    string ComputeBlobKzgProofTests = Path.Join(TestDir, "compute_blob_kzg_proof");
    string VerifyKzgProofTests = Path.Join(TestDir, "verify_kzg_proof");
    string VerifyBlobKzgProofTests = Path.Join(TestDir, "verify_blob_kzg_proof");
    string VerifyBlobKzgProofBatchTests = Path.Join(TestDir, "verify_blob_kzg_proof_batch");

    ///////////////////////////////////////////////////////////////////////////
    // Helper Functions
    ///////////////////////////////////////////////////////////////////////////

    private static byte[] GetBytes(string path)
    {
        var hex = File.ReadAllText(path);
        return Convert.FromHexString(hex);
    }

    public static byte[] GetFlatBytes(List<string> strings)
    {
        List<byte[]> stringBytes = new List<byte[]>();
        foreach (string str in strings)
        {
            stringBytes.Add(GetBytes(str));
        }

        byte[] flatBytes = new byte[stringBytes.Sum(b => b.Length)];
        int offset = 0;
        foreach (byte[] bytes in stringBytes)
        {
            System.Buffer.BlockCopy(bytes, 0, flatBytes, offset, bytes.Length);
            offset += bytes.Length;
        }

        return flatBytes;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Testing Setup/Teardown
    ///////////////////////////////////////////////////////////////////////////

    [OneTimeSetUp]
    public void Setup()
    {
        ts = Ckzg.LoadTrustedSetup("trusted_setup.txt");
    }

    [OneTimeTearDown]
    public void Teardown()
    {
        Ckzg.FreeTrustedSetup(ts);
    }


    ///////////////////////////////////////////////////////////////////////////
    // BlobToKzgCommitment
    ///////////////////////////////////////////////////////////////////////////

    public class BlobToKzgCommitmentInput
    {
        public string blob { get; set; } = null!;
    }

    public class BlobToKzgCommitmentTest
    {
        public BlobToKzgCommitmentInput input { get; set; } = null!;
        public string? output { get; set; } = null!;
    }

    [TestCase]
    public void TestSetupLoaded()
    {
        Assert.That(ts, Is.Not.EqualTo(IntPtr.Zero));
    }

    [TestCase]
    public unsafe void TestBlobToKzgCommitment()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        foreach (String testFile in matcher.GetResultsInFullPath(BlobToKZGCommitmentTests))
        {
            String? yaml = File.ReadAllText(testFile);
            var deserializer = new YamlDotNet.Serialization.DeserializerBuilder().Build();
            var test = deserializer.Deserialize<BlobToKzgCommitmentTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] commitment = new byte[48];
            byte[] blob = GetBytes(test.input.blob);

            fixed (byte *pCommitment = commitment, pBlob = blob)
            {
                Ckzg.Ret ret = Ckzg.BlobToKzgCommitment(pCommitment, pBlob, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    string? commitmentStr = test.output;
                    Assert.That(commitmentStr, Is.Not.EqualTo(null));
                    byte[] expectedCommitment = GetBytes(commitmentStr);
                    Assert.That(commitment, Is.EqualTo(expectedCommitment));
                }
                else
                {
                    Assert.That(test.output, Is.EqualTo(null));
                }
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // ComputeKzgProof
    ///////////////////////////////////////////////////////////////////////////

    public class ComputeKzgProofInput
    {
        public string blob { get; set; } = null!;
        public string z { get; set; } = null!;
    }

    public class ComputeKzgProofTest
    {
        public ComputeKzgProofInput input { get; set; } = null!;
        public string? output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestComputeKzgProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        foreach (String testFile in matcher.GetResultsInFullPath(ComputeKzgProofTests))
        {
            String? yaml = File.ReadAllText(testFile);
            var deserializer = new YamlDotNet.Serialization.DeserializerBuilder().Build();
            var test = deserializer.Deserialize<ComputeKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] proof = new byte[48];
            byte[] blob = GetBytes(test.input.blob);
            byte[] z = GetBytes(test.input.z);

            fixed (byte *pProof = proof, pBlob = blob, pZ = z)
            {
                Ckzg.Ret ret = Ckzg.ComputeKzgProof(pProof, pBlob, pZ, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    string? proofStr = test.output;
                    Assert.That(proofStr, Is.Not.EqualTo(null));
                    byte[] expectedProof = GetBytes(proofStr);
                    Assert.That(proof, Is.EqualTo(expectedProof));
                }
                else
                {
                    Assert.That(test.output, Is.EqualTo(null));
                }
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // ComputeBlobKzgProof
    ///////////////////////////////////////////////////////////////////////////

    public class ComputeBlobKzgProofInput
    {
        public string blob { get; set; } = null!;
    }

    public class ComputeBlobKzgProofTest
    {
        public ComputeBlobKzgProofInput input { get; set; } = null!;
        public string? output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestComputeBlobKzgProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        foreach (String testFile in matcher.GetResultsInFullPath(ComputeBlobKzgProofTests))
        {
            String? yaml = File.ReadAllText(testFile);
            var deserializer = new YamlDotNet.Serialization.DeserializerBuilder().Build();
            var test = deserializer.Deserialize<ComputeBlobKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] proof = new byte[48];
            byte[] blob = GetBytes(test.input.blob);

            fixed (byte *pProof = proof, pBlob = blob)
            {
                Ckzg.Ret ret = Ckzg.ComputeBlobKzgProof(pProof, pBlob, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    string? proofStr = test.output;
                    Assert.That(proofStr, Is.Not.EqualTo(null));
                    byte[] expectedProof = GetBytes(proofStr);
                    Assert.That(proof, Is.EqualTo(expectedProof));
                }
                else
                {
                    Assert.That(test.output, Is.EqualTo(null));
                }
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // VerifyKzgProof
    ///////////////////////////////////////////////////////////////////////////

    public class VerifyKzgProofInput
    {
        public string commitment { get; set; } = null!;
        public string z { get; set; } = null!;
        public string y { get; set; } = null!;
        public string proof { get; set; } = null!;
    }

    public class VerifyKzgProofTest
    {
        public VerifyKzgProofInput input { get; set; } = null!;
        public bool? output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestVerifyKzgProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        foreach (String testFile in matcher.GetResultsInFullPath(VerifyKzgProofTests))
        {
            String? yaml = File.ReadAllText(testFile);
            var deserializer = new YamlDotNet.Serialization.DeserializerBuilder().Build();
            var test = deserializer.Deserialize<VerifyKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            bool valid = false;
            byte[] commitment = GetBytes(test.input.commitment);
            byte[] z = GetBytes(test.input.z);
            byte[] y = GetBytes(test.input.y);
            byte[] proof = GetBytes(test.input.proof);

            fixed (byte *pCommitment = commitment, pZ = z, pY = y, pProof = proof)
            {
                Ckzg.Ret ret = Ckzg.VerifyKzgProof(&valid, pCommitment, pZ, pY, pProof, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    Assert.That(valid, Is.EqualTo(test.output));
                }
                else
                {
                    Assert.That(test.output, Is.EqualTo(null));
                }
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // VerifyBlobKzgProof
    ///////////////////////////////////////////////////////////////////////////

    public class VerifyBlobKzgProofInput
    {
        public string blob { get; set; } = null!;
        public string commitment { get; set; } = null!;
        public string proof { get; set; } = null!;
    }

    public class VerifyBlobKzgProofTest
    {
        public VerifyBlobKzgProofInput input { get; set; } = null!;
        public bool? output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestVerifyBlobKzgProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        foreach (String testFile in matcher.GetResultsInFullPath(VerifyBlobKzgProofTests))
        {
            String? yaml = File.ReadAllText(testFile);
            var deserializer = new YamlDotNet.Serialization.DeserializerBuilder().Build();
            var test = deserializer.Deserialize<VerifyBlobKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            bool valid = false;
            byte[] blob = GetBytes(test.input.blob);
            byte[] commitment = GetBytes(test.input.commitment);
            byte[] proof = GetBytes(test.input.proof);

            fixed (byte *pBlob = blob, pCommitment = commitment, pProof = proof)
            {
                Ckzg.Ret ret = Ckzg.VerifyBlobKzgProof(&valid, pBlob, pCommitment, pProof, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    Assert.That(valid, Is.EqualTo(test.output));
                }
                else
                {
                    Assert.That(test.output, Is.EqualTo(null));
                }
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // VerifyBlobKzgProofBatch
    ///////////////////////////////////////////////////////////////////////////

    public class VerifyBlobKzgProofBatchInput
    {
        public List<string> blobs { get; set; } = null!;
        public List<string> commitments { get; set; } = null!;
        public List<string> proofs { get; set; } = null!;
    }

    public class VerifyBlobKzgProofBatchTest
    {
        public VerifyBlobKzgProofBatchInput input { get; set; } = null!;
        public bool? output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestVerifyBlobKzgProofBatch()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        foreach (String testFile in matcher.GetResultsInFullPath(VerifyBlobKzgProofBatchTests))
        {
            String? yaml = File.ReadAllText(testFile);
            var deserializer = new YamlDotNet.Serialization.DeserializerBuilder().Build();
            var test = deserializer.Deserialize<VerifyBlobKzgProofBatchTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            bool valid = false;
            byte[] blobs = GetFlatBytes(test.input.blobs);
            byte[] commitments = GetFlatBytes(test.input.commitments);
            byte[] proofs = GetFlatBytes(test.input.proofs);
            int count = blobs.Length / Ckzg.BytesPerBlob;

            fixed (byte *pBlobs = blobs, pCommitments = commitments, pProofs = proofs)
            {
                Ckzg.Ret ret = Ckzg.VerifyBlobKzgProofBatch(&valid, pBlobs, pCommitments, pProofs, count, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    Assert.That(valid, Is.EqualTo(test.output));
                }
                else
                {
                    Assert.That(test.output, Is.EqualTo(null));
                }
            }
        }
    }
}