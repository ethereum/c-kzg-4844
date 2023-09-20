namespace Ckzg;

public static partial class Ckzg
{
    public const ulong BytesPerFieldElement = 32;
    public const ulong BytesPerCommitment = 48;
    public const ulong BytesPerProof = 48;

    /// <summary>
    ///     Loads trusted setup settings from file.
    /// </summary>
    /// <param name="filename">Settings file path</param>
    /// <exception cref="ArgumentException">Thrown when the file path is not correct</exception>
    /// <exception cref="InvalidOperationException">Thrown when unable to load the setup</exception>
    /// <returns>Trusted setup settings as a pointer</returns>
    public static unsafe KzgSettings* LoadTrustedSetup(string filepath)
    {
        if (!File.Exists(filepath)) throw new ArgumentException("Trusted setup file does not exist", nameof(filepath));

        KzgSettings* ckzgSetup = InternalLoadTrustedSetup(filepath);

        if (ckzgSetup == null) throw new InvalidOperationException("Unable to load trusted setup");
        return ckzgSetup;
    }

    /// <summary>
    ///     Frees memory allocated for trusted setup settings.
    /// </summary>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <exception cref="ArgumentException">Thrown when settings are not correct</exception>

    public static unsafe void FreeTrustedSetup(KzgSettings* ckzgSetup)
    {
        ThrowOnUninitializedTrustedSetup(ckzgSetup);
        InternalFreeTrustedSetup(ckzgSetup);
    }

    /// <summary>
    ///     Calculates commitment for the blob.
    /// </summary>
    /// <param name="commitment">Preallocated buffer of <inheritdoc cref="BytesPerCommitment"/> bytes to receive the commitment</param>
    /// <param name="blob">Flatten array of blob elements</param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <exception cref="ArgumentException">Thrown when length of an argument is not correct or settings are not correct</exception>
    /// <exception cref="ApplicationException">Thrown when the library returns unexpected Error code</exception>
    /// <exception cref="InsufficientMemoryException">Thrown when the library has no enough memory to process</exception>
    public static unsafe void BlobToKzgCommitment(Span<byte> commitment, ReadOnlySpan<byte> blob, KzgSettings* ckzgSetup)
    {
        ThrowOnUninitializedTrustedSetup(ckzgSetup);
        ThrowOnInvalidLength(blob, nameof(blob), ckzgSetup->bytes_per_blob);
        ThrowOnInvalidLength(commitment, nameof(commitment), BytesPerCommitment);

        fixed (byte* commitmentPtr = commitment, blobPtr = blob)
        {
            KzgResult result = BlobToKzgCommitment(commitmentPtr, blobPtr, ckzgSetup);
            ThrowOnError(result);
        }
    }

    /// <summary>
    ///     Compute KZG proof at point `z` for the polynomial represented by `blob`.
    /// </summary>
    /// <param name="proof">Preallocated buffer of <inheritdoc cref="BytesPerProof"/> bytes to receive the proof</param>
    /// <param name="y">Preallocated buffer of <inheritdoc cref="BytesPerFieldElement"/> bytes to receive y</param>
    /// <param name="blob">Blob bytes</param>
    /// <param name="z">Z point</param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <exception cref="ArgumentException">Thrown when length of an argument is not correct or settings are not correct</exception>
    /// <exception cref="ApplicationException">Thrown when the library returns unexpected Error code</exception>
    /// <exception cref="InsufficientMemoryException">Thrown when the library has no enough memory to process</exception>
    public static unsafe void ComputeKzgProof(Span<byte> proof, Span<byte> y, ReadOnlySpan<byte> blob,
        ReadOnlySpan<byte> z, KzgSettings* ckzgSetup)
    {
        ThrowOnUninitializedTrustedSetup(ckzgSetup);
        ThrowOnInvalidLength(proof, nameof(proof), BytesPerProof);
        ThrowOnInvalidLength(y, nameof(y), BytesPerFieldElement);
        ThrowOnInvalidLength(blob, nameof(blob), ckzgSetup->bytes_per_blob);
        ThrowOnInvalidLength(z, nameof(z), BytesPerFieldElement);

        fixed (byte* proofPtr = proof, yPtr = y, blobPtr = blob, zPtr = z)
        {
            KzgResult result = ComputeKzgProof(proofPtr, yPtr, blobPtr, zPtr, ckzgSetup);
            ThrowOnError(result);
        }
    }

    /// <summary>
    ///     Given a blob, return the KZG proof that is used to verify it against the commitment.
    /// </summary>
    /// <param name="proof">Preallocated buffer of <inheritdoc cref="BytesPerProof"/> bytes to receive the proof</param>
    /// <param name="blob">Blob bytes</param>
    /// <param name="commitment">Commitment bytes</param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <exception cref="ArgumentException">Thrown when length of an argument is not correct or settings are not correct</exception>
    /// <exception cref="ApplicationException">Thrown when the library returns unexpected Error code</exception>
    /// <exception cref="InsufficientMemoryException">Thrown when the library has no enough memory to process</exception>
    public static unsafe void ComputeBlobKzgProof(Span<byte> proof, ReadOnlySpan<byte> blob,
        ReadOnlySpan<byte> commitment, KzgSettings* ckzgSetup)
    {
        ThrowOnUninitializedTrustedSetup(ckzgSetup);
        ThrowOnInvalidLength(proof, nameof(proof), BytesPerProof);
        ThrowOnInvalidLength(blob, nameof(blob), ckzgSetup->bytes_per_blob);
        ThrowOnInvalidLength(commitment, nameof(commitment), BytesPerCommitment);

        fixed (byte* proofPtr = proof, blobPtr = blob, commitmentPtr = commitment)
        {
            KzgResult result = ComputeBlobKzgProof(proofPtr, blobPtr, commitmentPtr, ckzgSetup);
            ThrowOnError(result);
        }
    }

    /// <summary>
    ///     Given a blob and a KZG proof, verify that the blob data corresponds to the provided commitment.
    /// </summary>
    /// <param name="commitment">Commitment bytes</param>
    /// <param name="z">Z bytes</param>
    /// <param name="y">Y bytes</param>
    /// <param name="proof">Proof bytes</param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <exception cref="ArgumentException">Thrown when length of an argument is not correct or settings are not correct</exception>
    /// <exception cref="ApplicationException">Thrown when the library returns unexpected Error code</exception>
    /// <exception cref="InsufficientMemoryException">Thrown when the library has no enough memory to process</exception>
    /// <returns>Verification result</returns>
    public static unsafe bool VerifyKzgProof(ReadOnlySpan<byte> commitment, ReadOnlySpan<byte> z, ReadOnlySpan<byte> y,
        ReadOnlySpan<byte> proof, KzgSettings* ckzgSetup)
    {

        ThrowOnUninitializedTrustedSetup(ckzgSetup);
        ThrowOnInvalidLength(commitment, nameof(commitment), BytesPerCommitment);
        ThrowOnInvalidLength(z, nameof(z), BytesPerFieldElement);
        ThrowOnInvalidLength(y, nameof(y), BytesPerFieldElement);
        ThrowOnInvalidLength(proof, nameof(proof), BytesPerProof);

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
    /// <param name="blob">Blob bytes</param>
    /// <param name="commitment">Commitment bytes</param>
    /// <param name="proof">Proof bytes</param>
    /// <param name="ckzgSetup">Trusted setup settings</param>
    /// <exception cref="ArgumentException">Thrown when length of an argument is not correct or settings are not correct</exception>
    /// <exception cref="ApplicationException">Thrown when the library returns unexpected Error code</exception>
    /// <exception cref="InsufficientMemoryException">Thrown when the library has no enough memory to process</exception>
    /// <returns>Verification result</returns>
    public static unsafe bool VerifyBlobKzgProof(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> commitment,
        ReadOnlySpan<byte> proof, KzgSettings* ckzgSetup)
    {
        ThrowOnUninitializedTrustedSetup(ckzgSetup);
        ThrowOnInvalidLength(blob, nameof(blob), ckzgSetup->bytes_per_blob);
        ThrowOnInvalidLength(commitment, nameof(proof), BytesPerCommitment);
        ThrowOnInvalidLength(proof, nameof(proof), BytesPerProof);

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
    /// <exception cref="ArgumentException">Thrown when length of an argument is not correct or settings are not correct</exception>
    /// <exception cref="ApplicationException">Thrown when the library returns unexpected Error code</exception>
    /// <exception cref="InsufficientMemoryException">Thrown when the library has no enough memory to process</exception>
    /// <returns>Verification result</returns>
    public static unsafe bool VerifyBlobKzgProofBatch(ReadOnlySpan<byte> blobs, ReadOnlySpan<byte> commitments,
        ReadOnlySpan<byte> proofs, ulong count, KzgSettings *ckzgSetup)
    {
        ThrowOnUninitializedTrustedSetup(ckzgSetup);
        ThrowOnInvalidLength(blobs, nameof(blobs), ckzgSetup->bytes_per_blob * count);
        ThrowOnInvalidLength(commitments, nameof(proofs), BytesPerCommitment * count);
        ThrowOnInvalidLength(proofs, nameof(proofs), BytesPerProof * count);

        fixed (byte* blobsPtr = blobs, commitmentsPtr = commitments, proofsPtr = proofs)
        {
            KzgResult kzgResult =
                VerifyBlobKzgProofBatch(out var result, blobsPtr, commitmentsPtr, proofsPtr, count, ckzgSetup);
            ThrowOnError(kzgResult);
            return result;
        }
    }

    #region Argument verification helpers
    private static void ThrowOnError(KzgResult result)
    {
        switch (result)
        {
            case KzgResult.BadArgs: throw new ArgumentException();
            case KzgResult.Malloc: throw new InsufficientMemoryException();
            case KzgResult.Ok:
                return;
            default:
                throw new ApplicationException("KZG returned unexpected result");
        }
    }

    private static unsafe void ThrowOnUninitializedTrustedSetup(KzgSettings* ckzgSetup)
    {
        if (ckzgSetup == null)
            throw new ArgumentException("Trusted setup is not initialized", nameof(ckzgSetup));
    }

    private static void ThrowOnInvalidLength(ReadOnlySpan<byte> data, string fieldName, ulong expectedLength)
    {
        if ((ulong)data.Length != expectedLength)
            throw new ArgumentException("Invalid data size", fieldName);
    }
    #endregion
}