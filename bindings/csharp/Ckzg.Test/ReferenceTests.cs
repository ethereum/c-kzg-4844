using Microsoft.Extensions.FileSystemGlobbing;
using NUnit.Framework;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace CkzgLib.Test;

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
    private static readonly string _blobToKzgCommitmentTests = Path.Join(TestDir, "blob_to_kzg_commitment");
    private static readonly string _computeKzgProofTests = Path.Join(TestDir, "compute_kzg_proof");
    private static readonly string _computeBlobKzgProofTests = Path.Join(TestDir, "compute_blob_kzg_proof");
    private static readonly string _verifyKzgProofTests = Path.Join(TestDir, "verify_kzg_proof");
    private static readonly string _verifyBlobKzgProofTests = Path.Join(TestDir, "verify_blob_kzg_proof");
    private static readonly string _verifyBlobKzgProofBatchTests = Path.Join(TestDir, "verify_blob_kzg_proof_batch");
    private static readonly string _computeCellsTests = Path.Join(TestDir, "compute_cells");
    private static readonly string _computeCellsAndKzgProofsTests = Path.Join(TestDir, "compute_cells_and_kzg_proofs");
    private static readonly string _recoverCellsAndKzgProofsTests = Path.Join(TestDir, "recover_cells_and_kzg_proofs");
    private static readonly string _verifyCellKzgProofBatchTests = Path.Join(TestDir, "verify_cell_kzg_proof_batch");

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

    public class BlobToKzgCommitmentInput
    {
        public string Blob { get; set; } = null!;
    }

    public class BlobToKzgCommitmentTest
    {
        public BlobToKzgCommitmentInput Input { get; set; } = null!;
        public string? Output { get; set; } = null!;
    }

    private static IEnumerable<BlobToKzgCommitmentTest> GetBlobToKzgCommitmentTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_blobToKzgCommitmentTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            BlobToKzgCommitmentTest test = _deserializer.Deserialize<BlobToKzgCommitmentTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetBlobToKzgCommitmentTests))]
    public void TestBlobToKzgCommitment(BlobToKzgCommitmentTest test)
    {
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

    #endregion

    #region ComputeKzgProof

    public class ComputeKzgProofInput
    {
        public string Blob { get; set; } = null!;
        public string Z { get; set; } = null!;
    }

    public class ComputeKzgProofTest
    {
        public ComputeKzgProofInput Input { get; set; } = null!;
        public List<string>? Output { get; set; } = null!;
    }

    private static IEnumerable<ComputeKzgProofTest> GetComputeKzgProofTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeKzgProofTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeKzgProofTest test = _deserializer.Deserialize<ComputeKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetComputeKzgProofTests))]
    public void TestComputeKzgProof(ComputeKzgProofTest test)
    {
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

    #endregion

    #region ComputeBlobKzgProof

    public class ComputeBlobKzgProofInput
    {
        public string Blob { get; set; } = null!;
        public string Commitment { get; set; } = null!;
    }

    public class ComputeBlobKzgProofTest
    {
        public ComputeBlobKzgProofInput Input { get; set; } = null!;
        public string? Output { get; set; } = null!;
    }

    private static IEnumerable<ComputeBlobKzgProofTest> GetComputeBlobKzgProofTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeBlobKzgProofTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeBlobKzgProofTest test = _deserializer.Deserialize<ComputeBlobKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetComputeBlobKzgProofTests))]
    public void TestComputeBlobKzgProof(ComputeBlobKzgProofTest test)
    {
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

    #endregion

    #region VerifyKzgProof

    public class VerifyKzgProofInput
    {
        public string Commitment { get; set; } = null!;
        public string Z { get; set; } = null!;
        public string Y { get; set; } = null!;
        public string Proof { get; set; } = null!;
    }

    public class VerifyKzgProofTest
    {
        public VerifyKzgProofInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    private static IEnumerable<VerifyKzgProofTest> GetVerifyKzgProofTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyKzgProofTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyKzgProofTest test = _deserializer.Deserialize<VerifyKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetVerifyKzgProofTests))]
    public void TestVerifyKzgProof(VerifyKzgProofTest test)
    {
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

    #endregion

    #region VerifyBlobKzgProof

    public class VerifyBlobKzgProofInput
    {
        public string Blob { get; set; } = null!;
        public string Commitment { get; set; } = null!;
        public string Proof { get; set; } = null!;
    }

    public class VerifyBlobKzgProofTest
    {
        public VerifyBlobKzgProofInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    private static IEnumerable<VerifyBlobKzgProofTest> GetVerifyBlobKzgProofTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyBlobKzgProofTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyBlobKzgProofTest test = _deserializer.Deserialize<VerifyBlobKzgProofTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetVerifyBlobKzgProofTests))]
    public void TestVerifyBlobKzgProof(VerifyBlobKzgProofTest test)
    {
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

    #endregion

    #region VerifyBlobKzgProofBatch

    public class VerifyBlobKzgProofBatchInput
    {
        public List<string> Blobs { get; set; } = null!;
        public List<string> Commitments { get; set; } = null!;
        public List<string> Proofs { get; set; } = null!;
    }

    public class VerifyBlobKzgProofBatchTest
    {
        public VerifyBlobKzgProofBatchInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    private static IEnumerable<VerifyBlobKzgProofBatchTest> GetVerifyBlobKzgProofBatchTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyBlobKzgProofBatchTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyBlobKzgProofBatchTest test = _deserializer.Deserialize<VerifyBlobKzgProofBatchTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetVerifyBlobKzgProofBatchTests))]
    public void TestVerifyBlobKzgProofBatch(VerifyBlobKzgProofBatchTest test)
    {
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

    #endregion

    #region ComputeCells

    public class ComputeCellsInput
    {
        public string Blob { get; set; } = null!;
    }

    public class ComputeCellsTest
    {
        public ComputeCellsInput Input { get; set; } = null!;
        public List<string>? Output { get; set; } = null!;
    }

    private static IEnumerable<ComputeCellsTest> GetComputeCellsTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeCellsTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeCellsTest test = _deserializer.Deserialize<ComputeCellsTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }


    [Test, TestCaseSource(nameof(GetComputeCellsTests))]
    public void TestComputeCells(ComputeCellsTest test)
    {
        byte[] cells = new byte[CellsPerExtBlob * Ckzg.BytesPerCell];
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

    #endregion

    #region ComputeCellsAndKzgProofs

    public class ComputeCellsAndKzgProofsInput
    {
        public string Blob { get; set; } = null!;
    }

    public class ComputeCellsAndKzgProofsTest
    {
        public ComputeCellsAndKzgProofsInput Input { get; set; } = null!;
        public List<List<string>>? Output { get; set; } = null!;
    }

    private static IEnumerable<ComputeCellsAndKzgProofsTest> GetComputeCellsAndKzgProofsTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_computeCellsAndKzgProofsTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            ComputeCellsAndKzgProofsTest test = _deserializer.Deserialize<ComputeCellsAndKzgProofsTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }


    [Test, TestCaseSource(nameof(GetComputeCellsAndKzgProofsTests))]
    public void TestComputeCellsAndKzgProofs(ComputeCellsAndKzgProofsTest test)
    {
        byte[] cells = new byte[CellsPerExtBlob * Ckzg.BytesPerCell];
        byte[] proofs = new byte[CellsPerExtBlob * Ckzg.BytesPerProof];
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

    #endregion

    #region RecoverCellsAndKzgProofs

    public class RecoverCellsAndKzgProofsInput
    {
        public List<UInt64> CellIndices { get; set; } = null!;
        public List<string> Cells { get; set; } = null!;
    }

    public class RecoverCellsAndKzgProofsTest
    {
        public RecoverCellsAndKzgProofsInput Input { get; set; } = null!;
        public List<List<string>>? Output { get; set; } = null!;
    }

    private static IEnumerable<RecoverCellsAndKzgProofsTest> GetRecoverCellsAndKzgProofsTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_recoverCellsAndKzgProofsTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            RecoverCellsAndKzgProofsTest test = _deserializer.Deserialize<RecoverCellsAndKzgProofsTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetRecoverCellsAndKzgProofsTests))]
    public void TestRecoverCellsAndKzgProofs(RecoverCellsAndKzgProofsTest test)
    {
        byte[] recoveredCells = new byte[CellsPerExtBlob * Ckzg.BytesPerCell];
        byte[] recoveredProofs = new byte[CellsPerExtBlob * Ckzg.BytesPerProof];
        UInt64[] cellIndices = test.Input.CellIndices.ToArray();
        byte[] cells = GetFlatBytes(test.Input.Cells);
        int numCells = cells.Length / Ckzg.BytesPerCell;

        try
        {
            Ckzg.RecoverCellsAndKzgProofs(recoveredCells, recoveredProofs, cellIndices, cells, numCells, _ts);
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

    #region VerifyCellKzgProofBatch

    public class VerifyCellKzgProofBatchInput
    {
        public List<string> Commitments { get; set; } = null!;
        public List<UInt64> CellIndices { get; set; } = null!;
        public List<string> Cells { get; set; } = null!;
        public List<string> Proofs { get; set; } = null!;
    }

    public class VerifyCellKzgProofBatchTest
    {
        public VerifyCellKzgProofBatchInput Input { get; set; } = null!;
        public bool? Output { get; set; } = null!;
    }

    private static IEnumerable<VerifyCellKzgProofBatchTest> GetVerifyCellKzgProofBatchTests()
    {
        Matcher matcher = new();
        matcher.AddIncludePatterns(new[] { "*/*/data.yaml" });
        IEnumerable<string> testFiles = matcher.GetResultsInFullPath(_verifyCellKzgProofBatchTests);
        foreach (string testFile in testFiles)
        {
            string yaml = File.ReadAllText(testFile);
            VerifyCellKzgProofBatchTest test = _deserializer.Deserialize<VerifyCellKzgProofBatchTest>(yaml);
            Assert.That(test, Is.Not.EqualTo(null));
            yield return test;
        }
    }

    [Test, TestCaseSource(nameof(GetVerifyCellKzgProofBatchTests))]
    public void TestVerifyCellKzgProofBatch(VerifyCellKzgProofBatchTest test)
    {
        byte[] commitments = GetFlatBytes(test.Input.Commitments);
        UInt64[] cellIndices = test.Input.CellIndices.ToArray();
        byte[] cells = GetFlatBytes(test.Input.Cells);
        byte[] proofs = GetFlatBytes(test.Input.Proofs);
        int numCells = cells.Length / Ckzg.BytesPerCell;

        try
        {
            bool isCorrect = Ckzg.VerifyCellKzgProofBatch(commitments, cellIndices, cells, proofs, numCells, _ts);
            Assert.That(isCorrect, Is.EqualTo(test.Output));
        }
        catch
        {
            Assert.That(test.Output, Is.EqualTo(null));
        }
    }

    #endregion
}