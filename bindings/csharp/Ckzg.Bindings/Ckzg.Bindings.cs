using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace CkzgLib;

public static partial class Ckzg
{
    static Ckzg() => AssemblyLoadContext.Default.ResolvingUnmanagedDll += LoadNativeLibrary;

    private static IntPtr LoadNativeLibrary(Assembly _, string path)
    {
        if (!path.Equals("ckzg", StringComparison.OrdinalIgnoreCase))
        {
            return IntPtr.Zero;
        }

        string platform =
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win" : "";
        string arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => "",
        };
        string extension =
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "so" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "dylib" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "dll" : "";

        return NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, $"runtimes/{platform}-{arch}/native/{path}.{extension}"));
    }

    [DllImport("ckzg", EntryPoint = "load_trusted_setup_wrap")]
    private static extern IntPtr InternalLoadTrustedSetup(string filename, UInt64 precompute);

    [DllImport("ckzg", EntryPoint = "free_trusted_setup_wrap", CallingConvention = CallingConvention.Cdecl)]
    private static extern void InternalFreeTrustedSetup(IntPtr ts);

    [DllImport("ckzg", EntryPoint = "blob_to_kzg_commitment", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult BlobToKzgCommitment(byte* commitment, byte* blob, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "compute_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult ComputeKzgProof(byte* proof_out, byte* y_out, byte* blob, byte* z, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "compute_blob_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult ComputeBlobKzgProof(byte* proof, byte* blob, byte* commitment, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "verify_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult VerifyKzgProof(out bool result, byte* commitment, byte* z,
        byte* y, byte* proof, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "verify_blob_kzg_proof", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult VerifyBlobKzgProof(out bool result, byte* blob, byte* commitment,
        byte* proof, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "verify_blob_kzg_proof_batch", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult VerifyBlobKzgProofBatch(out bool result, byte* blobs, byte* commitments,
        byte* proofs, UInt64 count, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "compute_cells_and_kzg_proofs", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult ComputeCellsAndKzgProofs(byte* cells, byte* proofs, byte* blob, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "recover_cells_and_kzg_proofs", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult RecoverCellsAndKzgProofs(byte* recovered_cells, byte* recovered_proofs,
        UInt64* cell_indices, byte* cells, UInt64 num_cells, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "verify_cell_kzg_proof_batch", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult VerifyCellKzgProofBatch(out bool result, byte* commitments,
        UInt64* cell_indices, byte* cells, byte* proofs, UInt64 num_cells, IntPtr ts);

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