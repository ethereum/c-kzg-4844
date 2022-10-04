using System;
using System.Numerics;
using System.Text;
using System.Runtime.InteropServices;

class ckzg {
  [DllImport("ckzg.dll", EntryPoint="hello")]
  public static extern uint hello(uint a);

  [DllImport("ckzg.dll", EntryPoint="bytes_to_bls_field_wrap")]
  private static extern IntPtr bytes_to_bls_field_wrap(byte[] bytes);

  public static IntPtr bytes_to_bls_field(byte[] bytes) {
    return bytes_to_bls_field_wrap(bytes);
  }

  [DllImport("ckzg.dll", EntryPoint="uint64s_from_bls_field")]
  private static extern IntPtr uint64s_from_bls_field(IntPtr fr);

  [DllImport("ckzg.dll", EntryPoint="free")]
  private static extern void free(IntPtr p);

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
    Console.WriteLine("OK");
    Console.WriteLine(ckzg.hello(32));
    byte[] b = new byte[32];
    b[0] = 11;
    b[8] = 1;
    IntPtr fr = ckzg.bytes_to_bls_field(b);
    Console.WriteLine(ckzg.int_from_bls_field(fr));
  }
}
