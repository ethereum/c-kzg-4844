using System.Security.Cryptography;

namespace Ckzg;

public static partial class Ckzg
{
    public const int BytesPerFieldElement = 32;
    public const int FieldElementsPerBlob = 4096;
    public const int BytesPerBlob = BytesPerFieldElement * FieldElementsPerBlob;
    public const int BytesPerCommitment = 48;
    public const int BytesPerProof = 48;
    public const int BytesScalar = 32;

    private static readonly ThreadLocal<SHA256> _sha256 = new(SHA256.Create);

    /// <summary>
    /// </summary>
    /// <param name="commitment"></param>
    /// <param name="hashBuffer"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    public static bool TryComputeCommitmentV1(ReadOnlySpan<byte> commitment, Span<byte> hashBuffer)
    {
        const int bytesPerHash = 32;
        const int kzgBlobHashVersionV1 = 1;

        if (commitment.Length != BytesPerCommitment) throw new ArgumentException("Incorrect size", nameof(commitment));
        if (hashBuffer.Length != bytesPerHash) throw new ArgumentException("Incorrect size", nameof(commitment));
        if (_sha256.Value!.TryComputeHash(commitment, hashBuffer, out _))
        {
            hashBuffer[0] = kzgBlobHashVersionV1;
            return true;
        }

        return false;
    }

    /// <summary>
    ///     Load trusted setup settings from file
    /// </summary>
    /// <param name="filename">Settings file path</param>
    /// <returns>Trusted setup settings as a pointer or <c>0</c> in case of failure</returns>
    public static IntPtr LoadTrustedSetup(string filename)
    {
        if (!File.Exists(filename)) throw new ArgumentException("Trusted setup file does not exist", nameof(filename));

        IntPtr ckzgSetup = InternalLoadTrustedSetup(filename);

        if (ckzgSetup == IntPtr.Zero) throw new InvalidOperationException("Unable to load trusted setup");
        return ckzgSetup;
    }

    /// <summary>
    ///     Frees memory allocated for trusted setup settings
    /// </summary>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    public static void FreeTrustedSetup(IntPtr ckzgSetup)
    {
        if (ckzgSetup == IntPtr.Zero)
            throw new ArgumentException("Trusted setup is not initialized", nameof(ckzgSetup));

        InternalFreeTrustedSetup(ckzgSetup);
    }

    /// <summary>
    ///     Calculates commitment for the blob
    /// </summary>
    /// <param name="commitment">Preallocated buffer of <inheritdoc cref="CommitmentLength" /> bytes to receive the commitment</param>
    /// <param name="blob">Flatten array of blob elements</param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="InsufficientMemoryException"></exception>
    /// <returns>Returns error code or <c>0</c> if successful</returns>
    public static unsafe void BlobToKzgCommitment(Span<byte> commitment, ReadOnlySpan<byte> blob, IntPtr ckzgSetup)
    {
        if (blob.Length != BytesPerBlob) throw new ArgumentException("Invalid blob size", nameof(blob));

        if (commitment.Length != BytesPerCommitment)
            throw new ArgumentException("Invalid commitment size", nameof(commitment));

        if (ckzgSetup == IntPtr.Zero) throw new InvalidOperationException("KZG is not initialized");

        fixed (byte* commitmentPtr = commitment, blobPtr = blob)
        {
            KzgResult result = BlobToKzgCommitment(commitmentPtr, blobPtr, ckzgSetup);
            ThrowOnError(result);
        }
    }

    private static void ThrowOnError(KzgResult result)
    {
        switch (result)
        {
            case KzgResult.BadArgs: throw new ArgumentException();
            case KzgResult.Malloc: throw new InsufficientMemoryException();
            case KzgResult.Error: throw new Exception();
            case KzgResult.Ok:
                return;
            default:
                throw new ArgumentOutOfRangeException("KZG result", "KZG returned unexpected result");
        }
    }

    /// <summary>
    ///     Compute KZG proof at point `z` for the polynomial represented by `blob`.
    /// </summary>
    /// <param name="proof">Preallocated buffer of <inheritdoc cref="ProofLength" /> bytes to receive the proof</param>
    /// <param name="blob">Blob byte array</param>
    /// <param name="z"></param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <returns>Returns error code or <c>0</c> if successful</returns>
    public static unsafe void ComputeKzgProof(Span<byte> proof, ReadOnlySpan<byte> blob, ReadOnlySpan<byte> z,
        IntPtr ckzgSetup)
    {
        if (proof.Length != BytesPerProof) throw new ArgumentException("Invalid proof size", nameof(proof));

        if (blob.Length != BytesPerBlob) throw new ArgumentException("Invalid blob size", nameof(blob));

        if (z.Length != BytesScalar) throw new ArgumentException("Invalid z size", nameof(z));

        if (ckzgSetup == IntPtr.Zero) throw new InvalidOperationException("KZG is not initialized");

        fixed (byte* proofPtr = proof, blobPtr = blob, zPtr = z)
        {
            KzgResult result = ComputeKzgProof(proofPtr, blobPtr, zPtr, ckzgSetup);
            ThrowOnError(result);
        }
    }

    /// <summary>
    ///     Given a blob, return the KZG proof that is used to verify it against the commitment.
    /// </summary>
    /// <param name="proof">Preallocated buffer of <inheritdoc cref="ProofLength" /> bytes to receive the proof</param>
    /// <param name="blob">Blob byte array</param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <returns>Returns error code or <c>0</c> if successful</returns>
    public static unsafe void ComputeBlobKzgProof(Span<byte> proof, ReadOnlySpan<byte> blob, IntPtr ckzgSetup)
    {
        if (proof.Length != BytesPerProof) throw new ArgumentException("Invalid proof size", nameof(proof));

        if (blob.Length != BytesPerBlob) throw new ArgumentException("Invalid blob size", nameof(blob));

        if (ckzgSetup == IntPtr.Zero) throw new InvalidOperationException("KZG is not initialized");

        fixed (byte* proofPtr = proof, blobPtr = blob)
        {
            KzgResult result = ComputeBlobKzgProof(proofPtr, blobPtr, ckzgSetup);
            ThrowOnError(result);
        }
    }

    public static unsafe bool VerifyKzgProof(ReadOnlySpan<byte> commitment, ReadOnlySpan<byte> z, ReadOnlySpan<byte> y,
        ReadOnlySpan<byte> proof, IntPtr ckzgSetup)
    {
        if (commitment.Length != BytesPerCommitment)
            throw new ArgumentException("Invalid commitment size", nameof(commitment));

        if (z.Length != BytesScalar) throw new ArgumentException("Invalid z size", nameof(z));

        if (y.Length != BytesScalar) throw new ArgumentException("Invalid y size", nameof(y));

        if (proof.Length != BytesPerProof) throw new ArgumentException("Invalid proof size", nameof(proof));

        if (ckzgSetup == IntPtr.Zero) throw new InvalidOperationException("KZG is not initialized");

        fixed (byte* commitmentPtr = commitment, zPtr = z, yPtr = y, proofPtr = proof)
        {
            KzgResult kzgResult = VerifyKzgProof(out var result, commitmentPtr, zPtr, yPtr, proofPtr, ckzgSetup);
            ThrowOnError(kzgResult);
            return result;
        }
    }

    /// <summary>
    ///     Given a blob and a KZG proof, verify that the blob data corresponds to the provided commitment.
    /// </summary>
    /// <param name="blob"></param>
    /// <param name="commitment"></param>
    /// <param name="proof"></param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <returns></returns>
    public static unsafe bool VerifyBlobKzgProof(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> commitment,
        ReadOnlySpan<byte> proof, IntPtr ckzgSetup)
    {
        if (blob.Length != BytesPerBlob) throw new ArgumentException("Invalid blob size", nameof(blob));

        if (commitment.Length != BytesScalar) throw new ArgumentException("Invalid z size", nameof(commitment));

        if (proof.Length != BytesPerProof) throw new ArgumentException("Invalid proof size", nameof(proof));

        if (ckzgSetup == IntPtr.Zero) throw new InvalidOperationException("KZG is not initialized");

        fixed (byte* blobPtr = blob, commitmentPtr = commitment, proofPtr = proof)
        {
            KzgResult kzgResult = VerifyBlobKzgProof(out var result, blobPtr, commitmentPtr, proofPtr, ckzgSetup);
            ThrowOnError(kzgResult);
            return result;
        }
    }

    /// <summary>
    ///     Given a list of blobs and blob KZG proofs, verify that they correspond to the provided commitments.
    /// </summary>
    /// <param name="blobs">Blobs as a flattened byte array</param>
    /// <param name="commitments">Commitments as a flattened byte array</param>
    /// <param name="proofs">Proofs as a flattened byte array</param>
    /// <param name="count">The number of blobs/commitments/proofs</param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <returns></returns>
    public static unsafe bool VerifyBlobKzgProofBatch(ReadOnlySpan<byte> blobs, ReadOnlySpan<byte> commitments,
        ReadOnlySpan<byte> proofs, int count, IntPtr ckzgSetup)
    {
        if (blobs.Length != BytesPerBlob * count) throw new ArgumentException("Invalid blob size", nameof(blobs));

        if (commitments.Length != BytesScalar * count)
            throw new ArgumentException("Invalid y size", nameof(commitments));

        if (proofs.Length != BytesPerProof * count) throw new ArgumentException("Invalid proof size", nameof(proofs));

        if (ckzgSetup == IntPtr.Zero) throw new InvalidOperationException("KZG is not initialized");

        fixed (byte* blobsPtr = blobs, commitmentsPtr = commitments, proofsPtr = proofs)
        {
            KzgResult kzgResult =
                VerifyBlobKzgProofBatch(out var result, blobsPtr, commitmentsPtr, proofsPtr, count, ckzgSetup);
            ThrowOnError(kzgResult);
            return result;
        }
    }
}