using System;
using System.Text;

class ckzg {
  [global::System.Runtime.InteropServices.DllImport("ckzg.dll", EntryPoint="hello")]
  public static extern uint hello(uint a);
  [global::System.Runtime.InteropServices.DllImport("ckzg.dll", EntryPoint="bytes_to_bls_field_wrap")]
  public static extern void bytes_to_bls_field(byte[] b);
}

class tests {
  private static void Main(string[] args)
  {
    Console.WriteLine("OK");
    Console.WriteLine(ckzg.hello(32));
  }
}
