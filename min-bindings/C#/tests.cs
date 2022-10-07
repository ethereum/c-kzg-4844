using System;
using System.Numerics;
using System.Text;
using System.Runtime.InteropServices;

class ckzg {
  [DllImport("ckzg.dll", EntryPoint="bytes_to_bls_field_wrap")]
  public static extern IntPtr bytes_to_bls_field(byte[] bytes);

  [DllImport("ckzg.dll", EntryPoint="verify_kzg_proof_wrap")]
  public static extern int verify_kzg_proof(byte[] c, byte[] x, byte[] y, byte[] p, IntPtr ts);

  [DllImport("ckzg.dll", EntryPoint="evaluate_polynomial_wrap")]
  public static extern int evaluate_polynomial_in_evaluation_form(byte[] result, byte[] p, UInt64 n, byte[] z, IntPtr ts);

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
  // Convert.FromHexString replacement (since mono does not seem to have new enough C# libs)
  public static byte[] HexadecimalStringToByteArray(String hexadecimalString)
  {
    int length = hexadecimalString.Length;
    byte[] byteArray = new byte[length / 2];
    for (int i = 0; i < length; i += 2){
      byteArray[i / 2] = Convert.ToByte(hexadecimalString.Substring(i, 2), 16);
    }
    return byteArray;
  }

  private static void Main(string[] args)
  {
    Console.WriteLine("Test 1: verify_kzg_proof");

    IntPtr ts = ckzg.load_trusted_setup("../../src/trusted_setup.txt");
    System.Diagnostics.Trace.Assert(ts != IntPtr.Zero, "Failed to load trusted setup.");

    byte[] c = HexadecimalStringToByteArray("b91c022acf7bd3b63be69a4c19b781ea7a3d5df1cd66ceb7dd0f399610f0ee04695dace82e04bfb83af2b17d7319f87f");
    byte[] x = HexadecimalStringToByteArray("0345f802a75a6c0d9cc5b8a1e71642b8fa80b0a78938edc6da1e591149578d1a");
    byte[] y = HexadecimalStringToByteArray("3b17cab634c3795d311380f3bc93ce8e768efc0e2b9e79496cfc8f351594b472");
    byte[] p = HexadecimalStringToByteArray("a5ddd6da04c47a9cd4628beb8d55ebd2e930a64dfa29f876ebf393cfd6574d48a3ce96ac5a2af4a4f9ec9caa47d304d3");
    int result = ckzg.verify_kzg_proof(c, x, y, p, ts);
    System.Diagnostics.Trace.Assert(result == 1, "Verification failed");

    x[0] = 0x42;
    result = ckzg.verify_kzg_proof(c, x, y, p, ts);
    System.Diagnostics.Trace.Assert(result == 0, "Verification succeeded incorrectly");

    ckzg.free_trusted_setup(ts);

    Console.WriteLine("Test 2: evaluate_polynomial_in_evaluation_form");

    ts = ckzg.load_trusted_setup("../python/tiny_trusted_setup.txt");
    System.Diagnostics.Trace.Assert(ts != IntPtr.Zero, "Failed to load trusted setup.");

    p = HexadecimalStringToByteArray("10000000000000000d00000000000000000000000000000000000000000000000a000000000000000d00000000000000000000000000000000000000000000000b000000000001000d000376020003ecd0040376cecc518d00000000000000000c000000fffffeff0b5cfb8900a4ba6734d39e93390be8a5477d9d2953a7ed73");
    x = HexadecimalStringToByteArray("0200000000000000000000000000000000000000000000000000000000000000");
    UInt64 n = Convert.ToUInt64(p.Length) / 32;
    result = ckzg.evaluate_polynomial_in_evaluation_form(y, p, n, x, ts);
    System.Diagnostics.Trace.Assert(result == 0, "Evaluation failed");
    System.Diagnostics.Trace.Assert(y == HexadecimalStringToByteArray("1c000000000000000d0000000000000000000000000000000000000000000000"),
        "Evaluation produced incorrect value");

    x[11] = 0x11;
    result = ckzg.evaluate_polynomial_in_evaluation_form(y, p, n, x, ts);
    System.Diagnostics.Trace.Assert(result == 0, "Second evaluation failed");
    System.Diagnostics.Trace.Assert(y != HexadecimalStringToByteArray("1c000000000000000d0000000000000000000000000000000000000000000000"),
        "Second evaluation produced incorrect value");

    ckzg.free_trusted_setup(ts);

    Console.WriteLine("Tests passed");
  }
}
