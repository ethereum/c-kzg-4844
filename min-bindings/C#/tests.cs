using System;
using System.Numerics;
using System.Text;
using System.Runtime.InteropServices;

class ckzg {
  [DllImport("ckzg.dll", EntryPoint="bytes_to_bls_field_wrap")]
  public static extern IntPtr bytes_to_bls_field(byte[] bytes);

  [DllImport("ckzg.dll", EntryPoint="verify_kzg_proof_wrap")]
  public static extern int verify_kzg_proof(byte[] c, byte[] x, byte[] y, byte[] p, IntPtr ts);

  [DllImport("ckzg.dll", EntryPoint="load_trusted_setup_wrap")]
  public static extern IntPtr load_trusted_setup(string filename);

  [DllImport("ckzg.dll", EntryPoint="free_trusted_setup_wrap")]
  public static extern void free_trusted_setup(IntPtr ts);

  [DllImport("ckzg.dll", EntryPoint="free")]
  private static extern void free(IntPtr p);

  [DllImport("ckzg.dll", EntryPoint="uint64s_from_bls_field")]
  private static extern IntPtr uint64s_from_bls_field(IntPtr fr);

  public static BigInteger int_from_bls_field(IntPtr fr) {
    IntPtr uptr = uint64s_from_bls_field(fr);
    Int64[] int64s = new Int64[4];
    Marshal.Copy(uptr, int64s, 0, 4);
    free(uptr);
    BigInteger result = new BigInteger(0);
    BigInteger mult = new BigInteger(1);
    for (int i = 0; i < 4; i++) {
      result += Convert.ToUInt64(int64s[i]) * mult;
      mult *= BigInteger.Pow(2, 64);
    }
    return result;
  }
}

class tests {
  private static void Main(string[] args)
  {
    IntPtr ts = ckzg.load_trusted_setup("../../src/trusted_setup.txt");
    if (ts == IntPtr.Zero) {
      Console.WriteLine("Failed to load trusted setup.");
      return;
    }

    byte[] c = new byte[48];
    byte[] x = new byte[32];
    byte[] y = new byte[32];
    byte[] p = new byte[48];
    int result = ckzg.verify_kzg_proof(c, x, y, p, ts);
    Console.WriteLine(string.Format("Verification result: {0}", result));

    ckzg.free_trusted_setup(ts);

    byte[] b = new byte[32];
    b[0] = 11;
    b[8] = 1;
    IntPtr fr = ckzg.bytes_to_bls_field(b);
    Console.WriteLine(ckzg.int_from_bls_field(fr));
  }
}
