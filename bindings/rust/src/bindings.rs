/* automatically generated by rust-bindgen 0.61.0 */

include!("./consts.rs");

use std::ops::{Deref, DerefMut};

use libc::FILE;

pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_PROOF: usize = 48;
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

type byte = u8;
type limb_t = u64;
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_scalar {
    b: [byte; 32usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_fr {
    l: [limb_t; 4usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_fp {
    l: [limb_t; 6usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_fp2 {
    fp: [blst_fp; 2usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_fp6 {
    fp2: [blst_fp2; 3usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_fp12 {
    fp6: [blst_fp6; 2usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_p1 {
    x: blst_fp,
    y: blst_fp,
    z: blst_fp,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_p1_affine {
    x: blst_fp,
    y: blst_fp,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_p2 {
    x: blst_fp2,
    y: blst_fp2,
    z: blst_fp2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct blst_p2_affine {
    x: blst_fp2,
    y: blst_fp2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Bytes32 {
    bytes: [u8; 32],
}

impl Deref for Bytes32 {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Bytes48 {
    bytes: [u8; 48],
}

impl Deref for Bytes48 {
    type Target = [u8; 48];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Blob {
    bytes: [u8; BYTES_PER_BLOB],
}

impl Deref for Blob {
    type Target = [u8; BYTES_PER_BLOB];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for Blob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KZGProof {
    bytes: [u8; BYTES_PER_PROOF],
}

impl Deref for KZGProof {
    type Target = [u8; BYTES_PER_PROOF];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

type g1_t = blst_p1;
type g2_t = blst_p2;
type fr_t = blst_fr;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KZGCommitment {
    bytes: [u8; BYTES_PER_COMMITMENT],
}

impl Deref for KZGCommitment {
    type Target = [u8; BYTES_PER_COMMITMENT];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[repr(u32)]
#[doc = " The common return type for all routines in which something can go wrong."]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum C_KZG_RET {
    #[doc = "< Success!"]
    C_KZG_OK = 0,
    #[doc = "< The supplied data is invalid in some way."]
    C_KZG_BADARGS = 1,
    #[doc = "< Internal error - this should never occur and may indicate a bug in the library."]
    C_KZG_ERROR = 2,
    #[doc = "< Could not allocate memory."]
    C_KZG_MALLOC = 3,
}
#[doc = " Stores the setup and parameters needed for performing FFTs."]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FFTSettings {
    #[doc = "< The maximum size of FFT these settings support, a power of 2."]
    max_width: u64,
    #[doc = "< Ascending powers of the root of unity, size `width + 1`."]
    expanded_roots_of_unity: *const fr_t,
    #[doc = "< Descending powers of the root of unity, size `width + 1`."]
    reverse_roots_of_unity: *const fr_t,
    #[doc = "< Powers of the root of unity in bit-reversal permutation, size `width`."]
    roots_of_unity: *const fr_t,
}

#[doc = " Stores the setup and parameters needed for computing KZG proofs."]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KZGSettings {
    #[doc = "< The corresponding settings for performing FFTs."]
    fs: *const FFTSettings,
    #[doc = "< G1 group elements from the trusted setup, in Lagrange form bit-reversal permutation."]
    g1_values: *const g1_t,
    #[doc = "< G2 group elements from the trusted setup; both arrays have FIELD_ELEMENTS_PER_BLOB elements."]
    g2_values: *const g2_t,
}

/// Safety: FFTSettings is initialized once on calling `load_trusted_setup`. After
/// that, the struct is never modified. The memory for the arrays within `FFTSettings` and
/// `g1_values` and `g2_values` are only freed on calling `free_trusted_setup` which only happens
/// when we drop the struct.
unsafe impl Sync for KZGSettings {}
unsafe impl Send for KZGSettings {}

extern "C" {
    pub fn load_trusted_setup(
        out: *mut KZGSettings,
        g1_bytes: *const u8, /* n1 * 48 bytes */
        n1: usize,
        g2_bytes: *const u8, /* n2 * 96 bytes */
        n2: usize,
    ) -> C_KZG_RET;

    pub fn load_trusted_setup_file(out: *mut KZGSettings, in_: *mut FILE) -> C_KZG_RET;

    pub fn free_trusted_setup(s: *mut KZGSettings);

    pub fn compute_aggregate_kzg_proof(
        out: *mut KZGProof,
        blobs: *const Blob,
        n: usize,
        s: *const KZGSettings,
    ) -> C_KZG_RET;

    pub fn verify_aggregate_kzg_proof(
        out: *mut bool,
        blobs: *const Blob,
        commitments_bytes: *const Bytes48,
        n: usize,
        aggregated_proof_bytes: *const Bytes48,
        s: *const KZGSettings,
    ) -> C_KZG_RET;

    pub fn blob_to_kzg_commitment(
        out: *mut KZGCommitment,
        blob: *const Blob,
        s: *const KZGSettings,
    ) -> C_KZG_RET;

    pub fn verify_kzg_proof(
        out: *mut bool,
        commitment_bytes: *const Bytes48,
        z_bytes: *const Bytes32,
        y_bytes: *const Bytes32,
        proof_bytes: *const Bytes48,
        s: *const KZGSettings,
    ) -> C_KZG_RET;
}
