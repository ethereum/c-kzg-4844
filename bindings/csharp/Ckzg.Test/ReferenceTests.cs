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
        _ts = Ckzg.LoadTrustedSetup("trusted_setup.txt", 0);
        _deserializer = new DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance).Build();
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
    private readonly string _computeCellsTests = Path.Join(TestDir, "compute_cells");
    private readonly string _computeCellsAndKzgProofsTests = Path.Join(TestDir, "compute_cells_and_kzg_proofs");
    private readonly string _verifyCellKzgProofTests = Path.Join(TestDir, "verify_cell_kzg_proof");
    private readonly string _verifyCellKzgProofBatchTests = Path.Join(TestDir, "verify_cell_kzg_proof_batch");
    private readonly string _recoverAllCellsTests = Path.Join(TestDir, "recover_all_cells");
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

    #region ComputeCells

    private class ComputeCellsInput
    {
        public string Blob { get; set; } = null!;
    }

    private class ComputeCellsTest
    {
        public ComputeCellsInput Input { get; set; } = null!;
        public List<string>? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestComputeCells()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeCellsTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeCellsTest test = _deserializer.Deserialize<ComputeCellsTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] cells = new byte[Ckzg.CellsPerExtBlob * Ckzg.BytesPerCell];
            byte[] blob = GetBytes(test.Input.Blob);

            try
            {
                Ckzg.ComputeCells(cells, blob, _ts);
                Assert.That(test.Output, Is.Not.EqualTo(null));
                byte[] expectedCells = GetFlatBytes(test.Output);
                Assert.That(cells, Is.EqualTo(expectedCells));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region ComputeCellsAndKzgProofs

    private class ComputeCellsAndKzgProofsInput
    {
        public string Blob { get; set; } = null!;
    }

    private class ComputeCellsAndKzgProofsTest
    {
        public ComputeCellsAndKzgProofsInput Input { get; set; } = null!;
        public List<List<string>>? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestComputeCellsAndKzgProofs()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeCellsAndKzgProofsTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeCellsAndKzgProofsTest test = _deserializer.Deserialize<ComputeCellsAndKzgProofsTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] cells = new byte[Ckzg.CellsPerExtBlob * Ckzg.BytesPerCell];
            byte[] proofs = new byte[Ckzg.CellsPerExtBlob * Ckzg.BytesPerProof];
            byte[] blob = GetBytes(test.Input.Blob);

            try
            {
                Ckzg.ComputeCellsAndKzgProofs(cells, proofs, blob, _ts);
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
    }

    #endregion

    #region VerifyCellKzgProof

    private class VerifyCellKzgProofInput
    {
        public string Commitment { get; set; } = null!;
        public ulong CellId { get; set; } = 0!;
        public string Cell { get; set; } = null!;
        public string Proof { get; set; } = null!;
    }

    private class VerifyCellKzgProofTest
    {
        public VerifyCellKzgProofInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestVerifyCellKzgProof()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyCellKzgProofTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyCellKzgProofTest test = _deserializer.Deserialize<VerifyCellKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] commitment = GetBytes(test.Input.Commitment);
            ulong cellId = test.Input.CellId;
            byte[] cell = GetBytes(test.Input.Cell);
            byte[] proof = GetBytes(test.Input.Proof);
            try
            {
                bool isCorrect = Ckzg.VerifyCellKzgProof(commitment, cellId, cell, proof, _ts);
                Assert.That(isCorrect, Is.EqualTo(test.Output));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region VerifyCellKzgProofBatch

    private class VerifyCellKzgProofBatchInput
    {
        public List<string> RowCommitments { get; set; } = null!;
        public List<ulong> RowIndices { get; set; } = null!;
        public List<ulong> ColumnIndices { get; set; } = null!;
        public List<string> Cells { get; set; } = null!;
        public List<string> Proofs { get; set; } = null!;
    }

    private class VerifyCellKzgProofBatchTest
    {
        public VerifyCellKzgProofBatchInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestVerifyCellKzgProofBatch()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyCellKzgProofBatchTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyCellKzgProofBatchTest test = _deserializer.Deserialize<VerifyCellKzgProofBatchTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] rowCommitments = GetFlatBytes(test.Input.RowCommitments);
            ulong[] rowIndices = test.Input.RowIndices.ToArray();
            ulong[] columnIndices = test.Input.ColumnIndices.ToArray();
            byte[] cells = GetFlatBytes(test.Input.Cells);
            byte[] proofs = GetFlatBytes(test.Input.Proofs);
            int numCommitments = rowCommitments.Length / Ckzg.BytesPerCommitment;
            int numCells = cells.Length / Ckzg.BytesPerCell;

            try
            {
                bool isCorrect = Ckzg.VerifyCellKzgProofBatch(rowCommitments, numCommitments, rowIndices, columnIndices, cells, proofs, numCells, _ts);
                Assert.That(isCorrect, Is.EqualTo(test.Output));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion

    #region RecoverAllCells

    private class RecoverAllCellsInput
    {
        public List<ulong> CellIds { get; set; } = null!;
        public List<string> Cells { get; set; } = null!;
    }

    private class RecoverAllCellsTest
    {
        public RecoverAllCellsInput Input { get; set; } = null!;
        public List<string>? Output { get; set; } = null!;
    }

    [TestCase]
    public void TestRecoverAllCells()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });

        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_recoverAllCellsTests);
        Assert.That(testFiles.Count(), Is.GreaterThan(0));

        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            RecoverAllCellsTest test = _deserializer.Deserialize<RecoverAllCellsTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));

            byte[] recovered = new byte[Ckzg.CellsPerExtBlob * Ckzg.BytesPerCell];
            ulong[] cellIds = test.Input.CellIds.ToArray();
            byte[] cells = GetFlatBytes(test.Input.Cells);
            int numCells = cells.Length / Ckzg.BytesPerCell;

            try
            {
                Ckzg.RecoverAllCells(recovered, cellIds, cells, numCells, _ts);
                Assert.That(test.Output, Is.Not.EqualTo(null));
                byte[] expectedRecovered = GetFlatBytes(test.Output);
                Assert.That(recovered, Is.EqualTo(expectedRecovered));
            }
            catch
            {
                Assert.That(test.Output, Is.EqualTo(null));
            }
        }
    }

    #endregion
}