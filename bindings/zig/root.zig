const std = @import("std");
const testing = std.testing;
const Random = std.Random;

const c = @cImport({
    @cInclude("ckzg.h");
});

pub const BYTES_PER_BLOB = c.BYTES_PER_BLOB;
pub const BYTES_PER_CELL = c.BYTES_PER_CELL;
pub const BYTES_PER_COMMITMENT = c.BYTES_PER_COMMITMENT;
pub const BYTES_PER_FIELD_ELEMENT = c.BYTES_PER_FIELD_ELEMENT;
pub const BYTES_PER_PROOF = c.BYTES_PER_PROOF;
pub const CELLS_PER_EXT_BLOB = c.CELLS_PER_EXT_BLOB;
pub const FIELD_ELEMENTS_PER_BLOB = c.FIELD_ELEMENTS_PER_BLOB;
pub const FIELD_ELEMENTS_PER_CELL = c.FIELD_ELEMENTS_PER_CELL;

pub const Bytes32 = [32]u8;
pub const Bytes48 = [48]u8;
pub const KZGCommitment = Bytes48;
pub const KZGProof = Bytes48;
pub const Blob = [BYTES_PER_BLOB]u8;
pub const Cell = [BYTES_PER_CELL]u8;
pub const KZGSettings = c.KZGSettings;

pub const KZGError = error{
    BadArgs,
    InternalError,
    MallocError,
    UnknownError,
    TrustedSetupNotLoaded,
    TrustedSetupAlreadyLoaded,
    FileNotFound,
};

/// Embedded trusted setup data (~807KB). Only included when explicitly referenced.
pub const embedded_trusted_setup = @embedFile("trusted_setup.txt");

var settings: KZGSettings = undefined;
var loaded: bool = false;

fn makeErrorFromRet(ret: c.C_KZG_RET) KZGError {
    return switch (ret) {
        c.C_KZG_BADARGS => KZGError.BadArgs,
        c.C_KZG_ERROR => KZGError.InternalError,
        c.C_KZG_MALLOC => KZGError.MallocError,
        else => KZGError.UnknownError,
    };
}

/// Loads trusted setup from G1 and G2 point bytes.
pub fn loadTrustedSetup(
    g1_monomial_bytes: []const u8,
    g1_lagrange_bytes: []const u8,
    g2_monomial_bytes: []const u8,
    precompute: u64,
) KZGError!void {
    if (loaded) {
        return KZGError.TrustedSetupAlreadyLoaded;
    }

    const ret = c.load_trusted_setup(
        &settings,
        g1_monomial_bytes.ptr,
        g1_monomial_bytes.len,
        g1_lagrange_bytes.ptr,
        g1_lagrange_bytes.len,
        g2_monomial_bytes.ptr,
        g2_monomial_bytes.len,
        precompute,
    );

    if (ret == c.C_KZG_OK) {
        loaded = true;
        return;
    }

    return makeErrorFromRet(ret);
}

/// Loads trusted setup from text data. Pass `embedded_trusted_setup` or custom text.
pub fn loadTrustedSetupFromText(trusted_setup_text: []const u8, precompute: u64) KZGError!void {
    if (loaded) {
        return KZGError.TrustedSetupAlreadyLoaded;
    }

    var lines = std.mem.splitScalar(u8, trusted_setup_text, '\n');
    
    const n_g1_line = lines.next() orelse return KZGError.InternalError;
    const n_g1 = std.fmt.parseInt(usize, std.mem.trim(u8, n_g1_line, " \t\r\n"), 10) catch return KZGError.InternalError;
    if (n_g1 != 4096) return KZGError.InternalError;

    const n_g2_line = lines.next() orelse return KZGError.InternalError;
    const n_g2 = std.fmt.parseInt(usize, std.mem.trim(u8, n_g2_line, " \t\r\n"), 10) catch return KZGError.InternalError;
    if (n_g2 != 65) return KZGError.InternalError;

    var g1_lagrange_bytes = std.heap.page_allocator.alloc(u8, 48 * 4096) catch return KZGError.MallocError;
    defer std.heap.page_allocator.free(g1_lagrange_bytes);
    var g2_monomial_bytes = std.heap.page_allocator.alloc(u8, 96 * 65) catch return KZGError.MallocError;
    defer std.heap.page_allocator.free(g2_monomial_bytes);
    var g1_monomial_bytes = std.heap.page_allocator.alloc(u8, 48 * 4096) catch return KZGError.MallocError;
    defer std.heap.page_allocator.free(g1_monomial_bytes);

    for (0..4096) |i| {
        const line = lines.next() orelse return KZGError.InternalError;
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        _ = std.fmt.hexToBytes(g1_lagrange_bytes[i*48..(i+1)*48], trimmed) catch return KZGError.InternalError;
    }

    for (0..65) |i| {
        const line = lines.next() orelse return KZGError.InternalError;
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        _ = std.fmt.hexToBytes(g2_monomial_bytes[i*96..(i+1)*96], trimmed) catch return KZGError.InternalError;
    }

    for (0..4096) |i| {
        const line = lines.next() orelse return KZGError.InternalError;
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        _ = std.fmt.hexToBytes(g1_monomial_bytes[i*48..(i+1)*48], trimmed) catch return KZGError.InternalError;
    }

    const ret = c.load_trusted_setup(
        &settings,
        g1_monomial_bytes.ptr,
        g1_monomial_bytes.len,
        g1_lagrange_bytes.ptr,
        g1_lagrange_bytes.len,
        g2_monomial_bytes.ptr,
        g2_monomial_bytes.len,
        precompute,
    );

    if (ret == c.C_KZG_OK) {
        loaded = true;
        return;
    }

    return makeErrorFromRet(ret);
}

/// Loads trusted setup from file path.
pub fn loadTrustedSetupFile(file_path: []const u8, precompute: u64) KZGError!void {
    if (loaded) {
        return KZGError.TrustedSetupAlreadyLoaded;
    }

    var path_buf: [256]u8 = undefined;
    @memcpy(path_buf[0..file_path.len], file_path);
    path_buf[file_path.len] = 0;

    const file = std.c.fopen(@ptrCast(path_buf[0..file_path.len+1]), "r");
    if (file == null) {
        return KZGError.FileNotFound;
    }
    defer _ = std.c.fclose(file.?);

    const ret = c.load_trusted_setup_file(&settings, @ptrCast(@alignCast(file)), precompute);

    if (ret == c.C_KZG_OK) {
        loaded = true;
        return;
    }

    return makeErrorFromRet(ret);
}

/// Frees the loaded trusted setup.
pub fn freeTrustedSetup() KZGError!void {
    if (!loaded) {
        return KZGError.TrustedSetupNotLoaded;
    }
    c.free_trusted_setup(&settings);
    loaded = false;
}

/// Converts a blob to a KZG commitment.
pub fn blobToKZGCommitment(blob: *const Blob) KZGError!KZGCommitment {
    if (!loaded) {
        return KZGError.TrustedSetupNotLoaded;
    }

    var commitment: KZGCommitment = undefined;
    const ret = c.blob_to_kzg_commitment(
        @ptrCast(&commitment),
        @ptrCast(blob),
        &settings,
    );

    if (ret != c.C_KZG_OK) {
        return makeErrorFromRet(ret);
    }

    return commitment;
}

/// Computes a KZG proof for a blob at the given evaluation point.
pub fn computeKZGProof(blob: *const Blob, z_bytes: *const Bytes32) KZGError!struct { proof: KZGProof, y: Bytes32 } {
    if (!loaded) {
        return KZGError.TrustedSetupNotLoaded;
    }

    var proof: KZGProof = undefined;
    var y: Bytes32 = undefined;
    const ret = c.compute_kzg_proof(
        @ptrCast(&proof),
        @ptrCast(&y),
        @ptrCast(blob),
        @ptrCast(z_bytes),
        &settings,
    );

    if (ret != c.C_KZG_OK) {
        return makeErrorFromRet(ret);
    }

    return .{ .proof = proof, .y = y };
}

/// Verifies a KZG proof against a commitment.
pub fn verifyKZGProof(
    commitment_bytes: *const Bytes48,
    z_bytes: *const Bytes32,
    y_bytes: *const Bytes32,
    proof_bytes: *const Bytes48,
) KZGError!bool {
    if (!loaded) {
        @panic("trusted setup isn't loaded");
    }

    var result: bool = undefined;
    const ret = c.verify_kzg_proof(
        &result,
        @ptrCast(commitment_bytes),
        @ptrCast(z_bytes),
        @ptrCast(y_bytes),
        @ptrCast(proof_bytes),
        &settings,
    );

    if (ret != c.C_KZG_OK) {
        return makeErrorFromRet(ret);
    }

    return result;
}

/// Computes a KZG proof for a blob given its commitment.
pub fn computeBlobKZGProof(blob: *const Blob, commitment_bytes: *const Bytes48) KZGError!KZGProof {
    if (!loaded) {
        @panic("trusted setup isn't loaded");
    }

    var proof: KZGProof = undefined;
    const ret = c.compute_blob_kzg_proof(
        @ptrCast(&proof),
        @ptrCast(blob),
        @ptrCast(commitment_bytes),
        &settings,
    );

    if (ret != c.C_KZG_OK) {
        return makeErrorFromRet(ret);
    }

    return proof;
}

/// Verifies a blob KZG proof against its commitment.
pub fn verifyBlobKZGProof(
    blob: *const Blob,
    commitment_bytes: *const Bytes48,
    proof_bytes: *const Bytes48,
) KZGError!bool {
    if (!loaded) {
        @panic("trusted setup isn't loaded");
    }

    var result: bool = undefined;
    const ret = c.verify_blob_kzg_proof(
        &result,
        @ptrCast(blob),
        @ptrCast(commitment_bytes),
        @ptrCast(proof_bytes),
        &settings,
    );

    if (ret != c.C_KZG_OK) {
        return makeErrorFromRet(ret);
    }

    return result;
}

test "constants are defined" {
    try testing.expect(BYTES_PER_BLOB == 131072);
    try testing.expect(BYTES_PER_CELL == 2048);
    try testing.expect(BYTES_PER_COMMITMENT == 48);
    try testing.expect(BYTES_PER_FIELD_ELEMENT == 32);
    try testing.expect(BYTES_PER_PROOF == 48);
    try testing.expect(FIELD_ELEMENTS_PER_BLOB == 4096);
    try testing.expect(FIELD_ELEMENTS_PER_CELL == 64);
    try testing.expect(CELLS_PER_EXT_BLOB == 128);
}

test "type sizes are correct" {
    try testing.expect(@sizeOf(Bytes32) == 32);
    try testing.expect(@sizeOf(Bytes48) == 48);
    try testing.expect(@sizeOf(KZGCommitment) == 48);
    try testing.expect(@sizeOf(KZGProof) == 48);
    try testing.expect(@sizeOf(Blob) == BYTES_PER_BLOB);
    try testing.expect(@sizeOf(Cell) == BYTES_PER_CELL);
}

test "error handling" {
    const error_bad_args = KZGError.BadArgs;
    const error_internal = KZGError.InternalError;
    const error_malloc = KZGError.MallocError;
    const error_unknown = KZGError.UnknownError;
    
    try testing.expect(error_bad_args == KZGError.BadArgs);
    try testing.expect(error_internal == KZGError.InternalError);
    try testing.expect(error_malloc == KZGError.MallocError);
    try testing.expect(error_unknown == KZGError.UnknownError);
}

test "embedded trusted setup" {
    try testing.expect(embedded_trusted_setup.len > 800000);
    try testing.expect(std.mem.startsWith(u8, embedded_trusted_setup, "4096\n65\n"));
}

test "end to end KZG with embedded setup" {
    try loadTrustedSetupFromText(embedded_trusted_setup, 0);
    defer freeTrustedSetup() catch unreachable;
    
    var test_blob: Blob = undefined;
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    
    random.bytes(&test_blob);
    for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
        test_blob[i * BYTES_PER_FIELD_ELEMENT] = 0;
    }
    
    const commitment = try blobToKZGCommitment(&test_blob);
    const proof = try computeBlobKZGProof(&test_blob, &commitment);
    const is_valid = try verifyBlobKZGProof(&test_blob, &commitment, &proof);
    try testing.expect(is_valid);
    
    var wrong_proof = proof;
    wrong_proof[0] = wrong_proof[0] ^ 1;
    const should_fail = verifyBlobKZGProof(&test_blob, &commitment, &wrong_proof) catch false;
    try testing.expect(!should_fail);
}

test "end to end KZG functionality with file" {
    try loadTrustedSetupFile("src/trusted_setup.txt", 0);
    defer freeTrustedSetup() catch unreachable;
    
    var test_blob: Blob = undefined;
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    
    random.bytes(&test_blob);
    for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
        test_blob[i * BYTES_PER_FIELD_ELEMENT] = 0;
    }
    
    const commitment = try blobToKZGCommitment(&test_blob);
    const proof = try computeBlobKZGProof(&test_blob, &commitment);
    const is_valid = try verifyBlobKZGProof(&test_blob, &commitment, &proof);
    try testing.expect(is_valid);
    
    var wrong_proof = proof;
    wrong_proof[0] = wrong_proof[0] ^ 1;
    const should_fail = verifyBlobKZGProof(&test_blob, &commitment, &wrong_proof) catch false;
    try testing.expect(!should_fail);
}
