/* automatically generated by rust-bindgen 0.69.4 */

use libc::FILE;

pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_PROOF: usize = 48;
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
pub const BYTES_PER_BLOB: usize = 131072;
pub const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 8192;
pub const FIELD_ELEMENTS_PER_CELL: usize = 64;
pub const BYTES_PER_CELL: usize = 2048;
pub const CELLS_PER_EXT_BLOB: usize = 128;
pub type limb_t = u64;
#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct blst_fr {
    l: [limb_t; 4usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct blst_fp {
    l: [limb_t; 6usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct blst_fp2 {
    fp: [blst_fp; 2usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct blst_p1 {
    x: blst_fp,
    y: blst_fp,
    z: blst_fp,
}
#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct blst_p1_affine {
    x: blst_fp,
    y: blst_fp,
}
#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct blst_p2 {
    x: blst_fp2,
    y: blst_fp2,
    z: blst_fp2,
}
pub type fr_t = blst_fr;
pub type g1_t = blst_p1;
#[repr(C)]
#[doc = " The common return type for all routines in which something can go wrong."]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum C_KZG_RET {
    #[doc = "< Success!"]
    C_KZG_OK = 0,
    #[doc = "< The supplied data is invalid in some way."]
    C_KZG_BADARGS = 1,
    #[doc = "< Internal error - this should never occur."]
    C_KZG_ERROR = 2,
    #[doc = "< Could not allocate memory."]
    C_KZG_MALLOC = 3,
}
#[doc = " An array of 32 bytes. Represents an untrusted (potentially invalid) field element."]
#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Bytes32 {
    bytes: [u8; 32usize],
}
#[doc = " An array of 48 bytes. Represents an untrusted (potentially invalid) commitment/proof."]
#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Bytes48 {
    bytes: [u8; 48usize],
}
pub type g2_t = blst_p2;
#[doc = " Stores the setup and parameters needed for computing KZG proofs."]
#[repr(C)]
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct KZGSettings {
    #[doc = " Roots of unity for the subgroup of size `domain_size`.\n\n The array contains `domain_size + 1` elements, it starts and ends with Fr::one()."]
    roots_of_unity: *mut fr_t,
    #[doc = " Roots of unity for the subgroup of size `domain_size` in bit-reversed order.\n\n This array is derived by applying a bit-reversal permutation to `roots_of_unity`\n excluding the last element. Essentially:\n   `brp_roots_of_unity = bit_reversal_permutation(roots_of_unity[:-1])`\n\n The array contains `domain_size` elements."]
    brp_roots_of_unity: *mut fr_t,
    #[doc = " Roots of unity for the subgroup of size `domain_size` in reversed order.\n\n It is the reversed version of `roots_of_unity`. Essentially:\n    `reverse_roots_of_unity = reverse(roots_of_unity)`\n\n This array is primarily used in FFTs.\n The array contains `domain_size + 1` elements, it starts and ends with Fr::one()."]
    reverse_roots_of_unity: *mut fr_t,
    #[doc = " G1 group elements from the trusted setup in monomial form."]
    g1_values_monomial: *mut g1_t,
    #[doc = " G1 group elements from the trusted setup in Lagrange form and bit-reversed order."]
    g1_values_lagrange_brp: *mut g1_t,
    #[doc = " G2 group elements from the trusted setup in monomial form."]
    g2_values_monomial: *mut g2_t,
    #[doc = " Data used during FK20 proof generation."]
    x_ext_fft_columns: *mut *mut g1_t,
    #[doc = " The precomputed tables for fixed-base MSM."]
    tables: *mut *mut blst_p1_affine,
    #[doc = " The window size for the fixed-base MSM."]
    wbits: usize,
    #[doc = " The scratch size for the fixed-base MSM."]
    scratch_size: usize,
}
#[doc = " A basic blob data."]
#[repr(C)]
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Blob {
    bytes: [u8; 131072usize],
}
#[doc = " A single cell for a blob."]
#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Cell {
    bytes: [u8; 2048usize],
}
extern "C" {
    pub fn blob_to_kzg_commitment(
        out: *mut KZGCommitment,
        blob: *const Blob,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
    pub fn compute_kzg_proof(
        proof_out: *mut KZGProof,
        y_out: *mut Bytes32,
        blob: *const Blob,
        z_bytes: *const Bytes32,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
    pub fn compute_blob_kzg_proof(
        out: *mut KZGProof,
        blob: *const Blob,
        commitment_bytes: *const Bytes48,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
    pub fn verify_kzg_proof(
        ok: *mut bool,
        commitment_bytes: *const Bytes48,
        z_bytes: *const Bytes32,
        y_bytes: *const Bytes32,
        proof_bytes: *const Bytes48,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
    pub fn verify_blob_kzg_proof(
        ok: *mut bool,
        blob: *const Blob,
        commitment_bytes: *const Bytes48,
        proof_bytes: *const Bytes48,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
    pub fn verify_blob_kzg_proof_batch(
        ok: *mut bool,
        blobs: *const Blob,
        commitments_bytes: *const Bytes48,
        proofs_bytes: *const Bytes48,
        n: usize,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
    pub fn compute_cells_and_kzg_proofs(
        cells: *mut Cell,
        proofs: *mut KZGProof,
        blob: *const Blob,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
    pub fn recover_cells_and_kzg_proofs(
        recovered_cells: *mut Cell,
        recovered_proofs: *mut KZGProof,
        cell_indices: *const u64,
        cells: *const Cell,
        num_cells: usize,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
    pub fn verify_cell_kzg_proof_batch(
        ok: *mut bool,
        commitments_bytes: *const Bytes48,
        cell_indices: *const u64,
        cells: *const Cell,
        proofs_bytes: *const Bytes48,
        num_cells: usize,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
    #[doc = " The first 32 roots of unity in the finite field F_r. SCALE2_ROOT_OF_UNITY[i] is a 2^i'th root of\n unity.\n\n For element `{A, B, C, D}`, the field element value is `A + B * 2^64 + C * 2^128 + D * 2^192`.\n This format may be converted to an `fr_t` type via the blst_fr_from_uint64() function.\n\n The decimal values may be calculated with the following Python code:\n @code{.py}\n MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513\n PRIMITIVE_ROOT = 7\n [pow(PRIMITIVE_ROOT, (MODULUS - 1) // (2**i), MODULUS) for i in range(32)]\n @endcode\n\n Note: Being a \"primitive root\" in this context means that `r^k != 1` for any `k < q-1` where q is\n the modulus. So powers of r generate the field. This is also known as being a \"primitive\n element\".\n\n In the formula above, the restriction can be slightly relaxed to `r` being a non-square. This is\n easy to check: We just require that r^((q-1)/2) == -1. Instead of 7, we could use 10, 13, 14, 15,\n 20... to create the 2^i'th roots of unity below. Generally, there are a lot of primitive roots:\n https://crypto.stanford.edu/pbc/notes/numbertheory/gen.html"]
    pub static mut SCALE2_ROOT_OF_UNITY: [[u64; 4usize]; 32usize];
    pub fn load_trusted_setup(
        out: *mut KZGSettings,
        g1_monomial_bytes: *const u8,
        num_g1_monomial_bytes: usize,
        g1_lagrange_bytes: *const u8,
        num_g1_lagrange_bytes: usize,
        g2_monomial_bytes: *const u8,
        num_g2_monomial_bytes: usize,
        precompute: usize,
    ) -> C_KZG_RET;
    pub fn load_trusted_setup_file(
        out: *mut KZGSettings,
        in_: *mut FILE,
        precompute: usize,
    ) -> C_KZG_RET;
    pub fn free_trusted_setup(s: *mut KZGSettings);
}
