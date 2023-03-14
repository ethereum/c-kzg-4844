using Microsoft.Extensions.FileSystemGlobbing;
using NUnit.Framework;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Ckzg.Test;

[TestFixture]
public class ReferenceTests
{
    [OneTimeSetUp]
    public void Setup()
    {
        _ts = Ckzg.LoadTrustedSetup("trusted_setup.txt");
        _deserializer = new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).Build();
    }

    [OneTimeTearDown]
    public void Teardown()
    {
        Ckzg.FreeTrustedSetup(_ts);
    }

    [TestCase]
    public void TestSetupLoaded()
    {
        Assert.That(_ts, Is.Not.EqualTo(IntPtr.Zero));
    }

    private IntPtr _ts;
    private const string TestDir = "../../../../../../tests";
    private readonly string _blobToKzgCommitmentTests = Path.Join(TestDir, "blob_to_kzg_commitment");
    private readonly string _computeKzgProofTests = Path.Join(TestDir, "compute_kzg_proof");
    private readonly string _computeBlobKzgProofTests = Path.Join(TestDir, "compute_blob_kzg_proof");
    private readonly string _verifyKzgProofTests = Path.Join(TestDir, "verify_kzg_proof");
    private readonly string _verifyBlobKzgProofTests = Path.Join(TestDir, "verify_blob_kzg_proof");
    private readonly string _verifyBlobKzgProofBatchTests = Path.Join(TestDir, "verify_blob_kzg_proof_batch");
    private IDeserializer _deserializer;

    #region Helper Functions

    private static byte[] GetBytes(string hex)
    {
        return Convert.FromHexString(hex[2..]);
    }

    private static byte[] GetFlatBytes(List<string> strings)
    {
        List<byte[]> stringBytes = strings.Select(GetBytes).ToList();

        byte[] flatBytes = new byte[stringBytes.Sum(b => b.Length)];
        int offset = 0;
        foreach (byte[] bytes in stringBytes)
        {
            Buffer.BlockCopy(bytes, 0, flatBytes, offset, bytes.Length);
            offset += bytes.Length;
        }

        return flatBytes;
    }

    #endregion

    #region BlobToKzgCommitment

    private class BlobToKzgCommitmentInput
    {
        public string Blob { get; set; } = null!;
    }

    private class BlobToKzgCommitmentTest
    {
        public BlobToKzgCommitmentInput Input { get; set; } = null!;
        public string? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestBlobToKzgCommitment()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_blobToKzgCommitmentTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            BlobToKzgCommitmentTest test = _deserializer.Deserialize<BlobToKzgCommitmentTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] commitment = new byte[48];
            byte[] blob = GetBytes(test.Input.Blob);

            try
            {
                Ckzg.BlobToKzgCommitment(commitment, blob, _ts);
                Assert.That(test.Output, Is.Not.EqualTo(null));
                byte[] expectedCommitment = GetBytes(test.Output);
                Assert.That(commitment, Is.EqualTo(expectedCommitment));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region ComputeKzgProof

    private class ComputeKzgProofInput
    {
        public string Blob { get; set; } = null!;
        public string Z { get; set; } = null!;
    }

    private class ComputeKzgProofTest
    {
        public ComputeKzgProofInput Input { get; set; } = null!;
        public List<string>? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestComputeKzgProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeKzgProofTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeKzgProofTest test = _deserializer.Deserialize<ComputeKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] proof = new byte[48];
            byte[] y = new byte[32];
            byte[] blob = GetBytes(test.Input.Blob);
            byte[] z = GetBytes(test.Input.Z);

            try
            {
                Ckzg.ComputeKzgProof(proof, y, blob, z, _ts);
                Assert.That(test.Output, Is.Not.EqualTo(null));
                byte[] expectedProof = GetBytes(test.Output.ElementAt(0));
                Assert.That(proof, Is.EqualTo(expectedProof));
                byte[] expectedY = GetBytes(test.Output.ElementAt(1));
                Assert.That(y, Is.EqualTo(expectedY));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region ComputeBlobKzgProof

    private class ComputeBlobKzgProofInput
    {
        public string Blob { get; set; } = null!;
        public string Commitment { get; set; } = null!;
    }

    private class ComputeBlobKzgProofTest
    {
        public ComputeBlobKzgProofInput Input { get; set; } = null!;
        public string? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestComputeBlobKzgProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeBlobKzgProofTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeBlobKzgProofTest test = _deserializer.Deserialize<ComputeBlobKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] proof = new byte[48];
            byte[] blob = GetBytes(test.Input.Blob);
            byte[] commitment = GetBytes(test.Input.Commitment);

            try
            {
                Ckzg.ComputeBlobKzgProof(proof, blob, commitment, _ts);
                Assert.That(test.Output, Is.Not.EqualTo(null));
                byte[] expectedProof = GetBytes(test.Output);
                Assert.That(proof, Is.EqualTo(expectedProof));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region VerifyKzgProof

    private class VerifyKzgProofInput
    {
        public string Commitment { get; set; } = null!;
        public string Z { get; set; } = null!;
        public string Y { get; set; } = null!;
        public string Proof { get; set; } = null!;
    }

    private class VerifyKzgProofTest
    {
        public VerifyKzgProofInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestVerifyKzgProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyKzgProofTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyKzgProofTest test = _deserializer.Deserialize<VerifyKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] commitment = GetBytes(test.Input.Commitment);
            byte[] z = GetBytes(test.Input.Z);
            byte[] y = GetBytes(test.Input.Y);
            byte[] proof = GetBytes(test.Input.Proof);

            try
            {
                bool isCorrect = Ckzg.VerifyKzgProof(commitment, z, y, proof, _ts);
                Assert.That(isCorrect, Is.EqualTo(test.Output));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region VerifyBlobKzgProof

    private class VerifyBlobKzgProofInput
    {
        public string Blob { get; set; } = null!;
        public string Commitment { get; set; } = null!;
        public string Proof { get; set; } = null!;
    }

    private class VerifyBlobKzgProofTest
    {
        public VerifyBlobKzgProofInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestVerifyBlobKzgProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyBlobKzgProofTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyBlobKzgProofTest test = _deserializer.Deserialize<VerifyBlobKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] blob = GetBytes(test.Input.Blob);
            byte[] commitment = GetBytes(test.Input.Commitment);
            byte[] proof = GetBytes(test.Input.Proof);
            try
            {
                bool isCorrect = Ckzg.VerifyBlobKzgProof(blob, commitment, proof, _ts);
                Assert.That(isCorrect, Is.EqualTo(test.Output));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region VerifyBlobKzgProofBatch

    private class VerifyBlobKzgProofBatchInput
    {
        public List<string> Blobs { get; set; } = null!;
        public List<string> Commitments { get; set; } = null!;
        public List<string> Proofs { get; set; } = null!;
    }

    private class VerifyBlobKzgProofBatchTest
    {
        public VerifyBlobKzgProofBatchInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestVerifyBlobKzgProofBatch()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyBlobKzgProofBatchTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyBlobKzgProofBatchTest test = _deserializer.Deserialize<VerifyBlobKzgProofBatchTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] blobs = GetFlatBytes(test.Input.Blobs);
            byte[] commitments = GetFlatBytes(test.Input.Commitments);
            byte[] proofs = GetFlatBytes(test.Input.Proofs);
            int count = blobs.Length / Ckzg.BytesPerBlob;

            try
            {
                bool isCorrect = Ckzg.VerifyBlobKzgProofBatch(blobs, commitments, proofs, count, _ts);
                Assert.That(isCorrect, Is.EqualTo(test.Output));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion
}