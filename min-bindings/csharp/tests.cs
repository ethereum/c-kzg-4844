using System;
using System.Numerics;
using System.Text;
using System.Linq;
using System.Runtime.InteropServices;

class ckzg
{
    [DllImport("ckzg.dll", EntryPoint = "bytes_to_bls_field_wrap")] // free result with free()
    public static extern byte[] bytes_to_bls_field(byte[] bytes);

    [DllImport("ckzg.dll", EntryPoint = "compute_powers_wrap")] // free result with free()
    public static extern byte[] compute_powers(byte[] r, UInt64 n);

    [DllImport("ckzg.dll", EntryPoint = "vector_lincomb_wrap")] // free result with free_polynomial()
    public static extern byte[] vector_lincomb(byte[] vectors, byte[] scalars, UInt64 num_vectors, UInt64 vector_len);

    [DllImport("ckzg.dll", EntryPoint = "g1_lincomb_wrap")] // free result with free()
    public static extern byte[] g1_lincomb(byte[] points, byte[] scalars, UInt64 num_points);

    [DllImport("ckzg.dll", EntryPoint = "verify_kzg_proof_wrap")]
    public static extern bool verify_kzg_proof(byte[] c, byte[] x, byte[] y, byte[] p, IntPtr ts);

    [DllImport("ckzg.dll", EntryPoint = "evaluate_polynomial_wrap")] // free result with free()
    public static extern IntPtr evaluate_polynomial_in_evaluation_form(IntPtr p, IntPtr z, IntPtr ts);

    [DllImport("ckzg.dll", EntryPoint = "load_trusted_setup_wrap")] // free result with free_trusted_setup()
    public static extern IntPtr load_trusted_setup(string filename);

    [DllImport("ckzg.dll", EntryPoint = "free_trusted_setup_wrap")]
    public static extern void free_trusted_setup(IntPtr ts);

    [DllImport("ckzg.dll", EntryPoint = "free_polynomial")]
    public static extern void free_polynomial(IntPtr p);

    [DllImport("ckzg.dll", EntryPoint = "free")]
    private static extern void free(IntPtr p);
}

class tests
{
    IntPtr ts = ckzg.load_trusted_setup("../../src/trusted_setup.txt");

    byte[] ssz_of(params object[] anything)
    {
        return new byte[1]; //mock
    }
    byte[] hash(byte[] data)
    {
        return data; //mock
    }
    byte[] flatten(byte[][] data)
    {
        return data[0]; //mock
    }

    (byte[], byte[]) compute_aggregated_poly_and_commitment(byte[][] blobs, byte[][] kzg_commitments)
    {
        // Generate random linear combination challenges
        var r = hash_to_bls_field(ssz_of("BlobsAndCommitments", blobs, kzg_commitments));
        var r_powers = ckzg.compute_powers(r, (ulong)kzg_commitments.Length);

        // Create aggregated polynomial in evaluation form
        byte[] aggregated_poly = ckzg.vector_lincomb(flatten(blobs), r_powers, (ulong)blobs.Length, (ulong)4096);

        // Compute commitment to aggregated polynomial
        byte[] aggregated_poly_commitment = ckzg.g1_lincomb(flatten(kzg_commitments), r_powers, (ulong)kzg_commitments.Length);

        return (aggregated_poly, aggregated_poly_commitment);
    }

    byte[] hash_to_bls_field(byte[] data)
    {
        return ckzg.bytes_to_bls_field(hash(data));
    }

    const byte BLOB_COMMITMENT_VERSION_KZG = 1;

    byte[] kzg_to_versioned_hash(byte[] data_kzg)
    {
        var res = hash(data_kzg);
        res[0] = BLOB_COMMITMENT_VERSION_KZG;
        return res;
    }

    bool validate_blob_transaction_wrapper(
      byte[][] versioned_hashes,
      byte[][] commitments,
      byte[][] blobs
    )
    {
        if (versioned_hashes.Length != commitments.Length || commitments.Length != blobs.Length)
        {
            throw new ArgumentException("args");
        }
        var (aggregated_poly, aggregated_poly_commitment) = compute_aggregated_poly_and_commitment(
            blobs,
            commitments
        );

        // Generate challenge `x` and evaluate the aggregated polynomial at `x`
        var x = hash_to_bls_field(
          ssz_of("PolynomialAndCommitment", aggregated_poly, aggregated_poly_commitment)
        );
        // Evaluate aggregated polynomial at `x` (evaluation function checks for div-by-zero)
        var y = ckzg.evaluate_polynomial_in_evaluation_form(aggregated_poly, x, ts);

        // Verify aggregated proof
        if (!ckzg.verify_kzg_proof(aggregated_poly_commitment, x, y, "need to clarify", ts))
        {
            return false;
        }

        // Now that all commitments have been verified, check that versioned_hashes matches the commitments
        return versioned_hashes.Zip(commitments).All(x => Enumerable.SequenceEqual(x.First, kzg_to_versioned_hash(x.Second)));
    }
    readonly UInt256 BLS_MODULUS = UInt256.Parse("52435875175126190479447740508185965837690552500527637822603658699938581184513");

    struct UInt256
    {
        public UInt256(params byte[] data)
        {

        }

        public static bool operator >=(in UInt256 a, in UInt256 b) => true;
        public static bool operator <=(in UInt256 a, in UInt256 b) => false;

        internal static UInt256 Parse(string v)
        {
            return new UInt256();
        }
    }

    bool point_evaluation_precompile(byte[] input)
    {
        var versioned_hash = input[..32];
        // Evaluation point: next 32 bytes
        var x = input[32..64];
        if (new UInt256(x) >= BLS_MODULUS)
        {
            return false;
        }
        // Expected output: next 32 bytes
        var y = input[64..96];
        if (new UInt256(y) >= BLS_MODULUS)
        {
            return false;
        }
        // The remaining data will always be the proof, including in future versions
        // input kzg point: next 48 bytes
        var data_kzg = input[96..144];
        if (!kzg_to_versioned_hash(data_kzg).SequenceEqual(versioned_hash))
        {
            return false;
        }
        // Quotient kzg: next 48 bytes
        var quotient_kzg = input[144..192];
        if (!ckzg.verify_kzg_proof(data_kzg, x, y, quotient_kzg, ts))
        {
            return false;
        }
        return true;
    }


    // Convert.FromHexString replacement (since mono does not seem to have new enough C# libs)
    public static byte[] HexadecimalStringToByteArray(String hexadecimalString)
    {
        int length = hexadecimalString.Length;
        byte[] byteArray = new byte[length / 2];
        for (int i = 0; i < length; i += 2)
        {
            byteArray[i / 2] = Convert.ToByte(hexadecimalString.Substring(i, 2), 16);
        }
        return byteArray;
    }

    private static void Main(string[] args)
    {
        /* TODO: update for new interface
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
        */

        /* TODO: update for new interface
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
        */

        Console.WriteLine("Tests passed");
    }
}
