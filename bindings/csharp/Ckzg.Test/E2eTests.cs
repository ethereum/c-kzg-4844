using NUnit.Framework;
using System.IO;

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

    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }

    public static byte[] GetBytes(String path)
    {
        string hex = System.IO.File.ReadAllText(path);
        return StringToByteArray(hex);
    }

    public static byte[] GetFlatBytes(String path)
    {
        List<String> files = Directory.GetFiles(path).ToList();
        files.Sort();
        List<byte[]> filesBytes = new List<byte[]>();
        foreach (String file in files)
        {
            filesBytes.Add(GetBytes(file));
        }

        byte[] flatBytes = new byte[filesBytes.Sum(b => b.Length)];
        int offset = 0;
        foreach (byte[] bytes in filesBytes)
        {
            System.Buffer.BlockCopy(bytes, 0, flatBytes, offset, bytes.Length);
            offset += bytes.Length;
        }

        return flatBytes;
    }

    public static bool GetBoolean(String path)
    {
        return System.IO.File.ReadAllText(path).Contains("true");
    }

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

    [TestCase]
    public unsafe void TestBlobToKzgCommitment()
    {
        foreach (String test in Directory.GetDirectories(BlobToKZGCommitmentTests))
        {
            byte[] commitment = new byte[48];
            byte[] blob = GetBytes(Path.Join(test, "blob.txt"));
            fixed (byte *pCommitment = commitment, pBlob = blob)
            {
                Ckzg.Ret ret = Ckzg.BlobToKzgCommitment(pCommitment, pBlob, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    byte[] expectedCommitment = GetBytes(Path.Join(test, "commitment.txt"));
                    Assert.That(commitment, Is.EqualTo(expectedCommitment));
                }
                else
                {
                    Assert.False(System.IO.File.Exists(Path.Join(test, "commitment.txt")));
                }
            }
        }
    }

    [TestCase]
    public unsafe void TestComputeKzgProof()
    {
        foreach (String test in Directory.GetDirectories(ComputeKzgProofTests))
        {
            byte[] proof = new byte[48];
            byte[] blob = GetBytes(Path.Join(test, "blob.txt"));
            byte[] inputPoint = GetBytes(Path.Join(test, "input_point.txt"));
            fixed (byte *pProof = proof, pBlob = blob, pInputPoint = inputPoint)
            {
                Ckzg.Ret ret = Ckzg.ComputeKzgProof(pProof, pBlob, pInputPoint, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    byte[] expectedProof = GetBytes(Path.Join(test, "proof.txt"));
                    Assert.That(proof, Is.EqualTo(expectedProof));
                }
                else
                {
                    Assert.False(System.IO.File.Exists(Path.Join(test, "proof.txt")));
                }
            }
        }
    }

    [TestCase]
    public unsafe void TestComputeBlobKzgProof()
    {
        foreach (String test in Directory.GetDirectories(ComputeBlobKzgProofTests))
        {
            byte[] proof = new byte[48];
            byte[] blob = GetBytes(Path.Join(test, "blob.txt"));
            fixed (byte *pProof = proof, pBlob = blob)
            {
                Ckzg.Ret ret = Ckzg.ComputeBlobKzgProof(pProof, pBlob, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    byte[] expectedProof = GetBytes(Path.Join(test, "proof.txt"));
                    Assert.That(proof, Is.EqualTo(expectedProof));
                }
                else
                {
                    Assert.False(System.IO.File.Exists(Path.Join(test, "proof.txt")));
                }
            }
        }
    }

    [TestCase]
    public unsafe void TestVerifyKzgProof()
    {
        foreach (String test in Directory.GetDirectories(VerifyKzgProofTests))
        {
            bool ok = false;
            byte[] commitment = GetBytes(Path.Join(test, "commitment.txt"));
            byte[] inputPoint = GetBytes(Path.Join(test, "input_point.txt"));
            byte[] claimedValue = GetBytes(Path.Join(test, "claimed_value.txt"));
            byte[] proof = GetBytes(Path.Join(test, "proof.txt"));
            fixed (byte *pCommitment = commitment, pInputPoint = inputPoint, pClaimedValue = claimedValue, pProof = proof)
            {
                Ckzg.Ret ret = Ckzg.VerifyKzgProof(&ok, pCommitment, pInputPoint, pClaimedValue, pProof, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    bool expectedOk = GetBoolean(Path.Join(test, "ok.txt"));
                    Assert.That(ok, Is.EqualTo(expectedOk));
                }
                else
                {
                    Assert.False(System.IO.File.Exists(Path.Join(test, "ok.txt")));
                }
            }
        }
    }

    [TestCase]
    public unsafe void TestVerifyBlobKzgProof()
    {
        foreach (String test in Directory.GetDirectories(VerifyBlobKzgProofTests))
        {
            bool ok = false;
            byte[] blob = GetBytes(Path.Join(test, "blob.txt"));
            byte[] commitment = GetBytes(Path.Join(test, "commitment.txt"));
            byte[] proof = GetBytes(Path.Join(test, "proof.txt"));
            fixed (byte *pBlob = blob, pCommitment = commitment, pProof = proof)
            {
                Ckzg.Ret ret = Ckzg.VerifyBlobKzgProof(&ok, pBlob, pCommitment, pProof, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    bool expectedOk = GetBoolean(Path.Join(test, "ok.txt"));
                    Assert.That(ok, Is.EqualTo(expectedOk));
                }
                else
                {
                    Assert.False(System.IO.File.Exists(Path.Join(test, "ok.txt")));
                }
            }
        }
    }

    [TestCase]
    public unsafe void TestVerifyBlobKzgProofBatch()
    {
        foreach (String test in Directory.GetDirectories(VerifyBlobKzgProofBatchTests))
        {
            bool ok = false;
            byte[] blobs = GetFlatBytes(Path.Join(test, "blobs"));
            byte[] commitments = GetFlatBytes(Path.Join(test, "commitments"));
            byte[] proofs = GetFlatBytes(Path.Join(test, "proofs"));
            int count = blobs.Length / Ckzg.BytesPerBlob;
            fixed (byte *pBlobs = blobs, pCommitments = commitments, pProofs = proofs)
            {
                Ckzg.Ret ret = Ckzg.VerifyBlobKzgProofBatch(&ok, pBlobs, pCommitments, pProofs, count, ts);
                if (ret == Ckzg.Ret.Ok)
                {
                    bool expectedOk = GetBoolean(Path.Join(test, "ok.txt"));
                    Assert.That(ok, Is.EqualTo(expectedOk));
                }
                else
                {
                    Assert.False(System.IO.File.Exists(Path.Join(test, "ok.txt")));
                }
            }
        }
    }
}