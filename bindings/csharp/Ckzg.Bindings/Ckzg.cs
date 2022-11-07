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
    public static unsafe extern void blob_to_kzg_commitment(byte[] retval, byte[] blob, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "compute_aggregate_kzg_proof_wrap", CallingConvention = CallingConvention.Cdecl)] // returns 0 on success
    public static unsafe extern int compute_aggregate_kzg_proof(byte[] retval, byte[] blobs, int n, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "verify_aggregate_kzg_proof_wrap", CallingConvention = CallingConvention.Cdecl)] // returns 0 on success
    public static unsafe extern int verify_aggregate_kzg_proof(byte[] blobs, byte[] commitments, int blobCount, byte[] proof, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "verify_kzg_proof_wrap", CallingConvention = CallingConvention.Cdecl)] // returns 0 on success
    public static extern int verify_kzg_proof(byte[/*48*/] commitment, byte[/*32*/] x, byte[/*32*/] y, byte[/*48*/] proof, IntPtr ts);

    [DllImport("ckzg", EntryPoint = "load_trusted_setup_wrap")] // free result with free_trusted_setup()
    public static extern IntPtr load_trusted_setup(string filename);

    [DllImport("ckzg", EntryPoint = "free_trusted_setup_wrap", CallingConvention = CallingConvention.Cdecl)]
    public static extern void free_trusted_setup(IntPtr ts);
}

