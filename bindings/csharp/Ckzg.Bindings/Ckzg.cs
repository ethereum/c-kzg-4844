using System;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace Ckzg;

public class Ckzg
{
    static Ckzg()
    {
        AssemblyLoadContext.Default.ResolvingUnmanagedDll += (assembly, path) =>
        {
            var a = $"runtimes/{(
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win" : "")}-{RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "x64",
                Architecture.Arm64 => "arm64",
                _ => ""
            }}/native/{path}.{(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "dll" : "so")}";

            return NativeLibrary.Load(a);
        };
    }

    [DllImport("ckzg", EntryPoint = "blob_to_kzg_commitment_wrap", CallingConvention = CallingConvention.Cdecl)]
    public unsafe static extern void BlobToKzgCommitment(byte* retval, byte* blob, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "compute_aggregate_kzg_proof_wrap", CallingConvention = CallingConvention.Cdecl)] // returns 0 on success
    public unsafe static extern int ComputeAggregateKzgProof(byte* retval, byte* blobs, int n, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "verify_aggregate_kzg_proof_wrap", CallingConvention = CallingConvention.Cdecl)] // returns 0 on success
    public unsafe static extern int VerifyAggregateKzgProof(byte* blobs, byte* commitments, int blobCount, byte* proof, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "verify_kzg_proof_wrap", CallingConvention = CallingConvention.Cdecl)] // returns 0 on success
    public unsafe static extern int VerifyKzgProof(byte* commitment, byte* x, byte* y, byte* proof, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "load_trusted_setup_wrap")] // free result with free_trusted_setup()
    public static extern IntPtr LoadTrustedSetup(string filename);

    [DllImport("ckzg", EntryPoint = "free_trusted_setup_wrap", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FreeTrustedSetup(IntPtr ts);
}

