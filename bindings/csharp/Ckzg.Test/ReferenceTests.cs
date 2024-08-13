using Microsoft.Extensions.FileSystemGlobbing;
using NUnit.Framework;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Ckzg.Test;

[TestFixture]
public class ReferenceTests
{
    // Clients should use NUMBER_OF_COLUMNS from the consensus specs.
    private const int CellsPerExtBlob = 128;
    private static IDeserializer _deserializer = new DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance).Build();

    [OneTimeSetUp]
    public void Setup()
    {
        _ts = Ckzg.LoadTrustedSetup("trusted_setup.txt", 0);
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
    private readonly string _blobToKZGCommitmentTests = Path.Join(TestDir, "blob_to_kzg_commitment");
    private readonly string _computeKZGProofTests = Path.Join(TestDir, "compute_kzg_proof");
    private readonly string _computeBlobKZGProofTests = Path.Join(TestDir, "compute_blob_kzg_proof");
    private readonly string _verifyKZGProofTests = Path.Join(TestDir, "verify_kzg_proof");
    private readonly string _verifyBlobKZGProofTests = Path.Join(TestDir, "verify_blob_kzg_proof");
    private readonly string _verifyBlobKZGProofBatchTests = Path.Join(TestDir, "verify_blob_kzg_proof_batch");
    private static readonly string _computeCellsAndKZGProofsTests = Path.Join(TestDir, "compute_cells_and_kzg_proofs");
    private static readonly string _recoverCellsAndKZGProofsTests = Path.Join(TestDir, "recover_cells_and_kzg_proofs");
    private static readonly string _verifyCellKZGProofBatchTests = Path.Join(TestDir, "verify_cell_kzg_proof_batch");

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

    #region BlobToKZGCommitment

    private class BlobToKZGCommitmentInput
    {
        public string Blob { get; set; } = null!;
    }

    private class BlobToKZGCommitmentTest
    {
        public BlobToKZGCommitmentInput Input { get; set; } = null!;
        public string? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestBlobToKZGCommitment()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_blobToKZGCommitmentTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            BlobToKZGCommitmentTest test = _deserializer.Deserialize<BlobToKZGCommitmentTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] commitment = new byte[48];
            byte[] blob = GetBytes(test.Input.Blob);

            try
            {
                Ckzg.BlobToKZGCommitment(commitment, blob, _ts);
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

    #region ComputeKZGProof

    private class ComputeKZGProofInput
    {
        public string Blob { get; set; } = null!;
        public string Z { get; set; } = null!;
    }

    private class ComputeKZGProofTest
    {
        public ComputeKZGProofInput Input { get; set; } = null!;
        public List<string>? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestComputeKZGProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeKZGProofTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeKZGProofTest test = _deserializer.Deserialize<ComputeKZGProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] proof = new byte[48];
            byte[] y = new byte[32];
            byte[] blob = GetBytes(test.Input.Blob);
            byte[] z = GetBytes(test.Input.Z);

            try
            {
                Ckzg.ComputeKZGProof(proof, y, blob, z, _ts);
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

    #region ComputeBlobKZGProof

    private class ComputeBlobKZGProofInput
    {
        public string Blob { get; set; } = null!;
        public string Commitment { get; set; } = null!;
    }

    private class ComputeBlobKZGProofTest
    {
        public ComputeBlobKZGProofInput Input { get; set; } = null!;
        public string? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestComputeBlobKZGProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeBlobKZGProofTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeBlobKZGProofTest test = _deserializer.Deserialize<ComputeBlobKZGProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] proof = new byte[48];
            byte[] blob = GetBytes(test.Input.Blob);
            byte[] commitment = GetBytes(test.Input.Commitment);

            try
            {
                Ckzg.ComputeBlobKZGProof(proof, blob, commitment, _ts);
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

    #region VerifyKZGProof

    private class VerifyKZGProofInput
    {
        public string Commitment { get; set; } = null!;
        public string Z { get; set; } = null!;
        public string Y { get; set; } = null!;
        public string Proof { get; set; } = null!;
    }

    private class VerifyKZGProofTest
    {
        public VerifyKZGProofInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestVerifyKZGProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyKZGProofTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyKZGProofTest test = _deserializer.Deserialize<VerifyKZGProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] commitment = GetBytes(test.Input.Commitment);
            byte[] z = GetBytes(test.Input.Z);
            byte[] y = GetBytes(test.Input.Y);
            byte[] proof = GetBytes(test.Input.Proof);

            try
            {
                bool isCorrect = Ckzg.VerifyKZGProof(commitment, z, y, proof, _ts);
                Assert.That(isCorrect, Is.EqualTo(test.Output));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region VerifyBlobKZGProof

    private class VerifyBlobKZGProofInput
    {
        public string Blob { get; set; } = null!;
        public string Commitment { get; set; } = null!;
        public string Proof { get; set; } = null!;
    }

    private class VerifyBlobKZGProofTest
    {
        public VerifyBlobKZGProofInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestVerifyBlobKZGProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyBlobKZGProofTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyBlobKZGProofTest test = _deserializer.Deserialize<VerifyBlobKZGProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] blob = GetBytes(test.Input.Blob);
            byte[] commitment = GetBytes(test.Input.Commitment);
            byte[] proof = GetBytes(test.Input.Proof);
            try
            {
                bool isCorrect = Ckzg.VerifyBlobKZGProof(blob, commitment, proof, _ts);
                Assert.That(isCorrect, Is.EqualTo(test.Output));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region VerifyBlobKZGProofBatch

    private class VerifyBlobKZGProofBatchInput
    {
        public List<string> Blobs { get; set; } = null!;
        public List<string> Commitments { get; set; } = null!;
        public List<string> Proofs { get; set; } = null!;
    }

    private class VerifyBlobKZGProofBatchTest
    {
        public VerifyBlobKZGProofBatchInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestVerifyBlobKZGProofBatch()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyBlobKZGProofBatchTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyBlobKZGProofBatchTest test = _deserializer.Deserialize<VerifyBlobKZGProofBatchTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] blobs = GetFlatBytes(test.Input.Blobs);
            byte[] commitments = GetFlatBytes(test.Input.Commitments);
            byte[] proofs = GetFlatBytes(test.Input.Proofs);
            int count = blobs.Length / Ckzg.BytesPerBlob;

            try
            {
                bool isCorrect = Ckzg.VerifyBlobKZGProofBatch(blobs, commitments, proofs, count, _ts);
                Assert.That(isCorrect, Is.EqualTo(test.Output));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region ComputeCellsAndKZGProofs

    public class ComputeCellsAndKZGProofsInput
    {
        public string Blob { get; set; } = null!;
    }

    public class ComputeCellsAndKZGProofsTest
    {
        public ComputeCellsAndKZGProofsInput Input { get; set; } = null!;
        public List<List<string>>? Output { get; set; } = null!;
    }

    private static IEnumerable<ComputeCellsAndKZGProofsTest> GetComputeCellsAndKZGProofsTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeCellsAndKZGProofsTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeCellsAndKZGProofsTest test = _deserializer.Deserialize<ComputeCellsAndKZGProofsTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }


    [Test, TestCaseSource(nameof(GetComputeCellsAndKZGProofsTests))]
    public void TestComputeCellsAndKZGProofs(ComputeCellsAndKZGProofsTest test)
    {
        byte[] cells = new byte[CellsPerExtBlob * Ckzg.BytesPerCell];
        byte[] proofs = new byte[CellsPerExtBlob * Ckzg.BytesPerProof];
        byte[] blob = GetBytes(test.Input.Blob);

        try
        {
            Ckzg.ComputeCellsAndKZGProofs(cells, proofs, blob, _ts);
            Assert.That(test.Output, Is.Not.EqualTo(null));
            byte[] expectedCells = GetFlatBytes(test.Output.ElementAt(0));
            Assert.That(cells, Is.EqualTo(expectedCells));
            byte[] expectedProofs = GetFlatBytes(test.Output.ElementAt(1));
            Assert.That(proofs, Is.EqualTo(expectedProofs));
        }
        catch
        {
            Assert.That(test.Output, Is.EqualTo(null));
        }
    }

    #endregion

    #region RecoverCellsAndKZGProofs

    public class RecoverCellsAndKZGProofsInput
    {
        public List<ulong> CellIndices { get; set; } = null!;
        public List<string> Cells { get; set; } = null!;
    }

    public class RecoverCellsAndKZGProofsTest
    {
        public RecoverCellsAndKZGProofsInput Input { get; set; } = null!;
        public List<List<string>>? Output { get; set; } = null!;
    }

    private static IEnumerable<RecoverCellsAndKZGProofsTest> GetRecoverCellsAndKZGProofsTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_recoverCellsAndKZGProofsTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            RecoverCellsAndKZGProofsTest test = _deserializer.Deserialize<RecoverCellsAndKZGProofsTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetRecoverCellsAndKZGProofsTests))]
    public void TestRecoverCellsAndKZGProofs(RecoverCellsAndKZGProofsTest test)
    {
        byte[] recoveredCells = new byte[CellsPerExtBlob * Ckzg.BytesPerCell];
        byte[] recoveredProofs = new byte[CellsPerExtBlob * Ckzg.BytesPerProof];
        ulong[] cellIndices = test.Input.CellIndices.ToArray();
        byte[] cells = GetFlatBytes(test.Input.Cells);
        int numCells = cells.Length / Ckzg.BytesPerCell;

        try
        {
            Ckzg.RecoverCellsAndKZGProofs(recoveredCells, recoveredProofs, cellIndices, cells, numCells, _ts);
            Assert.That(test.Output, Is.Not.EqualTo(null));
            byte[] expectedCells = GetFlatBytes(test.Output.ElementAt(0));
            Assert.That(recoveredCells, Is.EqualTo(expectedCells));
            byte[] expectedProofs = GetFlatBytes(test.Output.ElementAt(1));
            Assert.That(recoveredProofs, Is.EqualTo(expectedProofs));
        }
        catch
        {
            Assert.That(test.Output, Is.EqualTo(null));
        }
    }

    #endregion

    #region VerifyCellKZGProofBatch

    public class VerifyCellKZGProofBatchInput
    {
        public List<string> Commitments { get; set; } = null!;
        public List<ulong> CellIndices { get; set; } = null!;
        public List<string> Cells { get; set; } = null!;
        public List<string> Proofs { get; set; } = null!;
    }

    public class VerifyCellKZGProofBatchTest
    {
        public VerifyCellKZGProofBatchInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    private static IEnumerable<VerifyCellKZGProofBatchTest> GetVerifyCellKZGProofBatchTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyCellKZGProofBatchTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyCellKZGProofBatchTest test = _deserializer.Deserialize<VerifyCellKZGProofBatchTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetVerifyCellKZGProofBatchTests))]
    public void TestVerifyCellKZGProofBatch(VerifyCellKZGProofBatchTest test)
    {
        byte[] commitments = GetFlatBytes(test.Input.Commitments);
        ulong[] cellIndices = test.Input.CellIndices.ToArray();
        byte[] cells = GetFlatBytes(test.Input.Cells);
        byte[] proofs = GetFlatBytes(test.Input.Proofs);
        int numCells = cells.Length / Ckzg.BytesPerCell;

        try
        {
            bool isCorrect = Ckzg.VerifyCellKZGProofBatch(commitments, cellIndices, cells, proofs, numCells, _ts);
            Assert.That(isCorrect, Is.EqualTo(test.Output));
        }
        catch
        {
            Assert.That(test.Output, Is.EqualTo(null));
        }
    }

    #endregion
}