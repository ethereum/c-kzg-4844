using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace Ckzg;

public class Ckzg
{
    public const int BytesPerFieldElement = 32;
    public const int BytesPerBlob = BytesPerFieldElement * 4096;
    public const int BytesPerCommitment = 48;
    public const int BytesPerProof = 48;

    public enum Ret
    {
        Ok,
        BadArgs,
        Error,
        Malloc
    }

    static Ckzg() => AssemblyLoadContext.Default.ResolvingUnmanagedDll += (assembly, path) => NativeLibrary.Load($"runtimes/{(
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win" : "")}-{RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "x64",
                Architecture.Arm64 => "arm64",
                _ => ""
            }}/native/{path}.{(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "dll" : "so")}");

    /// <summary>
    /// Load trusted setup settings from file
    /// </summary>
    /// <param name="filename">Settings file path</param>
    /// <returns>Trusted setup settings as a pointer or <c>0</c> in case of failure</returns>
    [DllImport("ckzg", EntryPoint = "load_trusted_setup_wrap")]
    public static extern IntPtr LoadTrustedSetup(string filename);

    /// <summary>
    /// Frees memory allocated for trusted setup settings
    /// </summary>
    /// <param name="ts">Trusted setup settings</param>
    [DllImport("ckzg", EntryPoint = "free_trusted_setup_wrap", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FreeTrustedSetup(IntPtr ts);

    /// <summary>
    /// Calculates commitment for the blob
    /// </summary>
    /// <param name="commitment">Preallocated buffer of <inheritdoc cref="CommitmentLength"/> bytes to receive the commitment</param>
    /// <param name="blob">Flatten array of blob elements</param>
    /// <param name="ts">Trusted setup settings</param>
    /// <returns>Returns error code or <c>0</c> if successful</returns>
    [DllImport("ckzg", EntryPoint = "blob_to_kzg_commitment", CallingConvention = CallingConvention.Cdecl)]
    public unsafe static extern Ret BlobToKzgCommitment(byte* commitment, byte* blob, IntPtr ts);

    /// <summary>
    /// Compute KZG proof at point `z` for the polynomial represented by `blob`.
    /// </summary>
    /// <param name="proof">Preallocated buffer of <inheritdoc cref="ProofLength"/> bytes to receive the proof</param>
    /// <param name="blob">Blob byte array</param>
    /// <param name="z_bytes"></param>
    /// <param name="ts">Trusted setup settings</param>
    /// <returns>Returns error code or <c>0</c> if successful</returns>
    [DllImport("ckzg", EntryPoint = "compute_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    public unsafe static extern Ret ComputeKzgProof(byte* proof, byte* blob, byte* z_bytes, IntPtr ts);

    /// <summary>
    /// Given a blob, return the KZG proof that is used to verify it against the commitment.
    /// </summary>
    /// <param name="proof">Preallocated buffer of <inheritdoc cref="ProofLength"/> bytes to receive the proof</param>
    /// <param name="blob">Blob byte array</param>
    /// <param name="ts">Trusted setup settings</param>
    /// <returns>Returns error code or <c>0</c> if successful</returns>
    [DllImport("ckzg", EntryPoint = "compute_blob_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    public unsafe static extern Ret ComputeBlobKzgProof(byte* proof, byte* blob, IntPtr ts);

    /// <summary>
    ///
    /// </summary>
    /// <param name="commitment_bytes"></param>
    /// <param name="z_bytes"></param>
    /// <param name="y_bytes"></param>
    /// <param name="proof_bytes"></param>
    /// <param name="ts">Trusted setup settings</param>
    /// <returns></returns>
    [DllImport("ckzg", EntryPoint = "verify_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    public unsafe static extern Ret VerifyKzgProof(byte* commitment_bytes, byte* z_bytes, byte* y_bytes, byte* proof_bytes, IntPtr ts);

    /// <summary>
    /// Given a blob and a KZG proof, verify that the blob data corresponds to the provided commitment.
    /// </summary>
    /// <param name="blob"></param>
    /// <param name="commitment"></param>
    /// <param name="proof"></param>
    /// <param name="ts">Trusted setup settings</param>
    /// <returns></returns>
    [DllImport("ckzg", EntryPoint = "verify_blob_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    public unsafe static extern Ret VerifyBlobKzgProof(byte* blob, byte* commitment_bytes, byte* proof_bytes, IntPtr ts);

    /// <summary>
    /// Given a list of blobs and blob KZG proofs, verify that they correspond to the provided commitments.
    /// </summary>
    /// <param name="blobs">Blobs as a flattened byte array</param>
    /// <param name="commitments">Commitments as a flattened byte array</param>
    /// <param name="proofs">Proofs as a flattened byte array</param>
    /// <param name="count">The number of blobs/commitments/proofs</param>
    /// <param name="ts">Trusted setup settings</param>
    /// <returns></returns>
    [DllImport("ckzg", EntryPoint = "verify_blob_kzg_proof_batch", CallingConvention = CallingConvention.Cdecl)]
    public unsafe static extern Ret VerifyBlobKzgProofBatch(byte* blobs, byte* commitments_bytes, byte* proofs_bytes, int count, IntPtr ts);
}

