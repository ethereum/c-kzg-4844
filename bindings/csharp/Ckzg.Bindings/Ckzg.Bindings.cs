using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace Ckzg;

public struct KzgSettings {
    public ulong field_elements_per_blob;
    public ulong bytes_per_blob;
    /* The rest doesn't matter */
}

public static partial class Ckzg
{
    static Ckzg()
    {
        AssemblyLoadContext.Default.ResolvingUnmanagedDll += (_, path) =>
            path.Contains("ckzg", StringComparison.OrdinalIgnoreCase)
                ? NativeLibrary.Load($"runtimes/{(
                    RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" :
                    RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" :
                    RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win" : "")}-{RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.X64 => "x64",
                    Architecture.Arm64 => "arm64",
                    _ => ""
                }}/native/{path}.{(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "dll" : "so")}")
                : IntPtr.Zero;
    }

    [DllImport("ckzg", EntryPoint = "load_trusted_setup_wrap")]
    private static extern unsafe KzgSettings* InternalLoadTrustedSetup(string filename);

    [DllImport("ckzg", EntryPoint = "free_trusted_setup_wrap", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe void InternalFreeTrustedSetup(KzgSettings* ts);

    [DllImport("ckzg", EntryPoint = "blob_to_kzg_commitment", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult BlobToKzgCommitment(byte* commitment, byte* blob, KzgSettings* ts);

    [DllImport("ckzg", EntryPoint = "compute_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult ComputeKzgProof(byte* proof_out, byte* y_out, byte* blob, byte* z, KzgSettings* ts);

    [DllImport("ckzg", EntryPoint = "compute_blob_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult ComputeBlobKzgProof(byte* proof, byte* blob, byte* commitment, KzgSettings* ts);

    [DllImport("ckzg", EntryPoint = "verify_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult VerifyKzgProof(out bool result, byte* commitment, byte* z,
        byte* y, byte* proof, KzgSettings* ts);

    [DllImport("ckzg", EntryPoint = "verify_blob_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult VerifyBlobKzgProof(out bool result, byte* blob, byte* commitment,
        byte* proof, KzgSettings* ts);

    [DllImport("ckzg", EntryPoint = "verify_blob_kzg_proof_batch", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult VerifyBlobKzgProofBatch(out bool result, byte* blobs, byte* commitments,
        byte* proofs, ulong count, KzgSettings* ts);

    private enum KzgResult
    {
        // Success!
        Ok,
        // The supplied data is invalid in some way.
        BadArgs,
        // Internal error - this should never occur.
        Error,
        // Could not allocate memory.
        Malloc
    }
}