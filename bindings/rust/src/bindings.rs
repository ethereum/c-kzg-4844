/* automatically generated by rust-bindgen 0.61.0 */

use libc::FILE;

pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_PROOF: usize = 48;
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const BYTES_PER_BLOB: usize = 131072;

pub type byte = u8;
pub type limb_t = u64;
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_scalar {
    pub b: [byte; 32usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_fr {
    pub l: [limb_t; 4usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_fp {
    pub l: [limb_t; 6usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_fp2 {
    pub fp: [blst_fp; 2usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_fp6 {
    pub fp2: [blst_fp2; 3usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_fp12 {
    pub fp6: [blst_fp6; 2usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_p1 {
    pub x: blst_fp,
    pub y: blst_fp,
    pub z: blst_fp,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_p1_affine {
    pub x: blst_fp,
    pub y: blst_fp,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_p2 {
    pub x: blst_fp2,
    pub y: blst_fp2,
    pub z: blst_fp2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct blst_p2_affine {
    pub x: blst_fp2,
    pub y: blst_fp2,
}

pub const FIAT_SHAMIR_PROTOCOL_DOMAIN: [u8; 16usize] = [
    70, 83, 66, 76, 79, 66, 86, 69, 82, 73, 70, 89, 95, 86, 49, 95,
];
pub type g1_t = blst_p1;
pub type g2_t = blst_p2;
pub type fr_t = blst_fr;
pub type KZGCommitment = g1_t;
pub type KZGProof = g1_t;
pub type BLSFieldElement = fr_t;
pub type Blob = [u8; 131072usize];
#[repr(u32)]
#[doc = " The common return type for all routines in which something can go wrong."]
#[doc = ""]
#[doc = " @warning In the case of @p C_KZG_OK or @p C_KZG_BADARGS, the caller can assume that all memory allocated by the"]
#[doc = " called routines has been deallocated. However, in the case of @p C_KZG_ERROR or @p C_KZG_MALLOC being returned, these"]
#[doc = " are unrecoverable and memory may have been leaked."]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum C_KZG_RET {
    #[doc = "< Success!"]
    C_KZG_OK = 0,
    #[doc = "< The supplied data is invalid in some way"]
    C_KZG_BADARGS = 1,
    #[doc = "< Internal error - this should never occur and may indicate a bug in the library"]
    C_KZG_ERROR = 2,
    #[doc = "< Could not allocate memory"]
    C_KZG_MALLOC = 3,
}
#[doc = " Stores the setup and parameters needed for performing FFTs."]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FFTSettings {
    #[doc = "< The maximum size of FFT these settings support, a power of 2."]
    pub max_width: u64,
    #[doc = "< Ascending powers of the root of unity, size `width + 1`."]
    pub expanded_roots_of_unity: *const fr_t,
    #[doc = "< Descending powers of the root of unity, size `width + 1`."]
    pub reverse_roots_of_unity: *const fr_t,
    #[doc = "< Powers of the root of unity in bit-reversal permutation, size `width`."]
    pub roots_of_unity: *const fr_t,
}

#[test]
fn bindgen_test_layout_FFTSettings() {
    const UNINIT: ::std::mem::MaybeUninit<FFTSettings> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<FFTSettings>(),
        32usize,
        concat!("Size of: ", stringify!(FFTSettings))
    );
    assert_eq!(
        ::std::mem::align_of::<FFTSettings>(),
        8usize,
        concat!("Alignment of ", stringify!(FFTSettings))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).max_width) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(FFTSettings),
            "::",
            stringify!(max_width)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).expanded_roots_of_unity) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(FFTSettings),
            "::",
            stringify!(expanded_roots_of_unity)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).reverse_roots_of_unity) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(FFTSettings),
            "::",
            stringify!(reverse_roots_of_unity)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).roots_of_unity) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(FFTSettings),
            "::",
            stringify!(roots_of_unity)
        )
    );
}
#[doc = " Stores the setup and parameters needed for computing KZG proofs."]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KZGSettings {
    #[doc = "< The corresponding settings for performing FFTs"]
    pub fs: *const FFTSettings,
    #[doc = "< G1 group elements from the trusted setup, in Lagrange form bit-reversal permutation"]
    pub g1_values: *const g1_t,
    #[doc = "< G2 group elements from the trusted setup; both arrays have FIELD_ELEMENTS_PER_BLOB elements"]
    pub g2_values: *const g2_t,
}

/// Safety: FFTSettings is initialized once on calling `load_trusted_setup`. After
/// that, the struct is never modified. The memory for the arrays within `FFTSettings` and
/// `g1_values` and `g2_values` are only freed on calling `free_trusted_setup` which only happens
/// when we drop the struct.
unsafe impl Sync for KZGSettings {}
unsafe impl Send for KZGSettings {}

#[test]
fn bindgen_test_layout_KZGSettings() {
    const UNINIT: ::std::mem::MaybeUninit<KZGSettings> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<KZGSettings>(),
        24usize,
        concat!("Size of: ", stringify!(KZGSettings))
    );
    assert_eq!(
        ::std::mem::align_of::<KZGSettings>(),
        8usize,
        concat!("Alignment of ", stringify!(KZGSettings))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).fs) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(KZGSettings),
            "::",
            stringify!(fs)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).g1_values) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(KZGSettings),
            "::",
            stringify!(g1_values)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).g2_values) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(KZGSettings),
            "::",
            stringify!(g2_values)
        )
    );
}
extern "C" {
    #[doc = " Interface functions"]
    pub fn bytes_to_g1(out: *mut g1_t, in_: *const u8) -> C_KZG_RET;
}
extern "C" {
    pub fn bytes_from_g1(out: *mut u8, in_: *const g1_t);
}
extern "C" {
    pub fn bytes_to_bls_field(out: *mut BLSFieldElement, in_: *const u8);
}
extern "C" {
    pub fn load_trusted_setup_file(out: *mut KZGSettings, in_: *mut FILE) -> C_KZG_RET;
}
extern "C" {
    pub fn load_trusted_setup(
        out: *mut KZGSettings,
        g1_bytes: *const u8, /* n1 * 48 bytes */
        n1: usize,
        g2_bytes: *const u8, /* n2 * 96 bytes */
        n2: usize,
    ) -> C_KZG_RET;
}
extern "C" {
    pub fn free_trusted_setup(s: *mut KZGSettings);
}
extern "C" {
    pub fn compute_aggregate_kzg_proof(
        out: *mut KZGProof,
        blobs: *const Blob,
        n: usize,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
}
extern "C" {
    pub fn verify_aggregate_kzg_proof(
        out: *mut bool,
        blobs: *const Blob,
        expected_kzg_commitments: *const KZGCommitment,
        n: usize,
        kzg_aggregated_proof: *const KZGProof,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
}
extern "C" {
    pub fn blob_to_kzg_commitment(out: *mut KZGCommitment, blob: *mut u8, s: *const KZGSettings);
}
extern "C" {
    pub fn verify_kzg_proof(
        out: *mut bool,
        polynomial_kzg: *const KZGCommitment,
        z: *const u8,
        y: *const u8,
        kzg_proof: *const KZGProof,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
}
