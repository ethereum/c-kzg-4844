using NUnit.Framework;
using System.IO;
using System.Text.Json;

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

    public static byte[] GetBytes(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
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

    [SetUp]
    public void Setup()
    {
        ts = Ckzg.LoadTrustedSetup("trusted_setup.txt");
        Assert.That(ts, Is.Not.EqualTo(IntPtr.Zero));
    }

    [TearDown]
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

    public class BlobToKzgCommitmentOutput
    {
        public string? commitment { get; set; } = null!;
    }

    public class BlobToKzgCommitmentTest
    {
        public BlobToKzgCommitmentInput input { get; set; } = null!;
        public BlobToKzgCommitmentOutput output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestBlobToKzgCommitment()
    {

        foreach (String testFile in Directory.GetFiles(BlobToKZGCommitmentTests))
        {
            String? json = File.ReadAllText(testFile);
            BlobToKzgCommitmentTest? test = JsonSerializer.Deserialize<BlobToKzgCommitmentTest>(json);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] commitment = new byte[48];
            byte[] blob = GetBytes(test.input.blob);

            fixed (byte *pCommitment = commitment, pBlob = blob)
            {
                Ckzg.Ret ret = Ckzg.BlobToKzgCommitment(pCommitment, pBlob, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    string? commitmentStr = test.output.commitment;
                    Assert.That(commitmentStr, Is.Not.EqualTo(null));
                    byte[] expectedCommitment = GetBytes(commitmentStr);
                    Assert.That(commitment, Is.EqualTo(expectedCommitment));
                }
                else
                {
                    Assert.That(test.output.commitment, Is.EqualTo(null));
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
        public string input_point { get; set; } = null!;
    }

    public class ComputeKzgProofOutput
    {
        public string? proof { get; set; } = null!;
    }

    public class ComputeKzgProofTest
    {
        public ComputeKzgProofInput input { get; set; } = null!;
        public ComputeKzgProofOutput output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestComputeKzgProof()
    {
        foreach (String testFile in Directory.GetFiles(ComputeKzgProofTests))
        {
            String? json = File.ReadAllText(testFile);
            ComputeKzgProofTest? test = JsonSerializer.Deserialize<ComputeKzgProofTest>(json);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] proof = new byte[48];
            byte[] blob = GetBytes(test.input.blob);
            byte[] inputPoint = GetBytes(test.input.input_point);

            fixed (byte *pProof = proof, pBlob = blob, pInputPoint = inputPoint)
            {
                Ckzg.Ret ret = Ckzg.ComputeKzgProof(pProof, pBlob, pInputPoint, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    string? proofStr = test.output.proof;
                    Assert.That(proofStr, Is.Not.EqualTo(null));
                    byte[] expectedProof = GetBytes(proofStr);
                    Assert.That(proof, Is.EqualTo(expectedProof));
                }
                else
                {
                    Assert.That(test.output.proof, Is.EqualTo(null));
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

    public class ComputeBlobKzgProofOutput
    {
        public string? proof { get; set; } = null!;
    }

    public class ComputeBlobKzgProofTest
    {
        public ComputeBlobKzgProofInput input { get; set; } = null!;
        public ComputeBlobKzgProofOutput output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestComputeBlobKzgProof()
    {
        foreach (String testFile in Directory.GetFiles(ComputeBlobKzgProofTests))
        {
            String? json = File.ReadAllText(testFile);
            ComputeBlobKzgProofTest? test = JsonSerializer.Deserialize<ComputeBlobKzgProofTest>(json);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] proof = new byte[48];
            byte[] blob = GetBytes(test.input.blob);

            fixed (byte *pProof = proof, pBlob = blob)
            {
                Ckzg.Ret ret = Ckzg.ComputeBlobKzgProof(pProof, pBlob, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    string? proofStr = test.output.proof;
                    Assert.That(proofStr, Is.Not.EqualTo(null));
                    byte[] expectedProof = GetBytes(proofStr);
                    Assert.That(proof, Is.EqualTo(expectedProof));
                }
                else
                {
                    Assert.That(test.output.proof, Is.EqualTo(null));
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
        public string input_point { get; set; } = null!;
        public string claimed_value { get; set; } = null!;
        public string proof { get; set; } = null!;
    }

    public class VerifyKzgProofOutput
    {
        public bool? valid { get; set; } = null!;
    }

    public class VerifyKzgProofTest
    {
        public VerifyKzgProofInput input { get; set; } = null!;
        public VerifyKzgProofOutput output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestVerifyKzgProof()
    {
        foreach (String testFile in Directory.GetFiles(VerifyKzgProofTests))
        {
            String? json = File.ReadAllText(testFile);
            VerifyKzgProofTest? test = JsonSerializer.Deserialize<VerifyKzgProofTest>(json);
            Assert.That(test, Is.Not.EqualTo(null));

            bool valid = false;
            byte[] commitment = GetBytes(test.input.commitment);
            byte[] inputPoint = GetBytes(test.input.input_point);
            byte[] claimedValue = GetBytes(test.input.claimed_value);
            byte[] proof = GetBytes(test.input.proof);

            fixed (byte *pCommitment = commitment, pInputPoint = inputPoint, pClaimedValue = claimedValue, pProof = proof)
            {
                Ckzg.Ret ret = Ckzg.VerifyKzgProof(&valid, pCommitment, pInputPoint, pClaimedValue, pProof, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    Assert.That(valid, Is.EqualTo(test.output.valid));
                }
                else
                {
                    Assert.That(test.output.valid, Is.EqualTo(null));
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

    public class VerifyBlobKzgProofOutput
    {
        public bool? valid { get; set; } = null!;
    }

    public class VerifyBlobKzgProofTest
    {
        public VerifyBlobKzgProofInput input { get; set; } = null!;
        public VerifyBlobKzgProofOutput output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestVerifyBlobKzgProof()
    {
        foreach (String testFile in Directory.GetFiles(VerifyBlobKzgProofTests))
        {
            String? json = File.ReadAllText(testFile);
            VerifyBlobKzgProofTest? test = JsonSerializer.Deserialize<VerifyBlobKzgProofTest>(json);
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
                    Assert.That(valid, Is.EqualTo(test.output.valid));
                }
                else
                {
                    Assert.That(test.output.valid, Is.EqualTo(null));
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

    public class VerifyBlobKzgProofBatchOutput
    {
        public bool? valid { get; set; } = null!;
    }

    public class VerifyBlobKzgProofBatchTest
    {
        public VerifyBlobKzgProofBatchInput input { get; set; } = null!;
        public VerifyBlobKzgProofBatchOutput output { get; set; } = null!;
    }

    [TestCase]
    public unsafe void TestVerifyBlobKzgProofBatch()
    {
        foreach (String testFile in Directory.GetFiles(VerifyBlobKzgProofBatchTests))
        {
            String? json = File.ReadAllText(testFile);
            VerifyBlobKzgProofBatchTest? test = JsonSerializer.Deserialize<VerifyBlobKzgProofBatchTest>(json);
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
                    Assert.That(valid, Is.EqualTo(test.output.valid));
                }
                else
                {
                    Assert.That(test.output.valid, Is.EqualTo(null));
                }
            }
        }
    }
}