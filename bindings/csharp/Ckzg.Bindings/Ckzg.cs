using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace Ckzg;

public class Ckzg
{
    public const int CommitmentLength = 48;
    public const int BlobElementLength = 32;
    public const int BlobLength = BlobElementLength * 4096;
    public const int ProofLength = 48;

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
    /// Calculates commitment for the blob
    /// </summary>
    /// <param name="commitment">Prealocated buffer of <inheritdoc cref="CommitmentLength"/> bytes to receive the commitment</param>
    /// <param name="blob">Flatten array of blob elements</param>
    /// <param name="ts">Trusted setup settings</param>
    [DllImport("ckzg", EntryPoint = "blob_to_kzg_commitment_wrap", CallingConvention = CallingConvention.Cdecl)]
    public unsafe static extern void BlobToKzgCommitment(byte* commitment, byte* blob, IntPtr ts);


    /// <summary>
    /// Calculates aggregated proof for the blobs
    /// </summary>
    /// <param name="proof">Prealocated buffer of <inheritdoc cref="ProofLength"/> bytes to receive the proof</param>
    /// <param name="blobs">Blobs as a flatten byte array</param>
    /// <param name="count">Blobs count</param>
    /// <param name="ts">Trusted setup settings</param>
    /// <returns>Returns error code or <c>0</c> if succeed</returns>
    [DllImport("ckzg", EntryPoint = "compute_aggregate_kzg_proof_wrap", CallingConvention = CallingConvention.Cdecl)] // returns 0 on success
    public unsafe static extern int ComputeAggregatedKzgProof(byte* proof, byte* blobs, int count, IntPtr ts);


    /// <summary>
    /// Verify aggregated proof and commitments for the given blobs
    /// </summary>
    /// <param name="blobs">Blobs as a flatten byte array</param>
    /// <param name="commitments">Commitments as a flatten byte array</param>
    /// <param name="count">Blobs and commitments count</param>
    /// <param name="proof"></param>
    /// <param name="ts">Trusted setup settings</param>
    /// <returns>Returns error code or <c>0</c> if the proof is correct</returns>
    [DllImport("ckzg", EntryPoint = "verify_aggregate_kzg_proof_wrap", CallingConvention = CallingConvention.Cdecl)] // returns 0 on success
    public unsafe static extern int VerifyAggregatedKzgProof(byte* blobs, byte* commitments, int count, byte* proof, IntPtr ts);

    /// <summary>
    /// Verify the proof by point evaluation for the given commitment
    /// </summary>
    /// <param name="commitment">Commitment</param>
    /// <param name="z">Z</param>
    /// <param name="y">Y</param>
    /// <param name="proof">Proof</param>
    /// <param name="ts">Trusted setup settings</param>
    /// <returns>Returns error code or <c>0</c> if the proof is correct</returns>
    [DllImport("ckzg", EntryPoint = "verify_kzg_proof_wrap", CallingConvention = CallingConvention.Cdecl)] // returns 0 on success
    public unsafe static extern int VerifyKzgProof(byte* commitment, byte* z, byte* y, byte* proof, IntPtr ts);

    /// <summary>
    /// Load trusted setup settings from file
    /// </summary>
    /// <param name="filename">Settings file path</param>
    /// <returns>Trusted setup settings as a pointer or <c>0</c> in case of failure</returns>
    [DllImport("ckzg", EntryPoint = "load_trusted_setup_wrap")] // free result with free_trusted_setup()
    public static extern IntPtr LoadTrustedSetup(string filename);

    /// <summary>
    /// Frees memory allocated for trusted setup settings
    /// </summary>
    /// <param name="ts">Trusted setup settings</param>
    [DllImport("ckzg", EntryPoint = "free_trusted_setup_wrap", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FreeTrustedSetup(IntPtr ts);
}

