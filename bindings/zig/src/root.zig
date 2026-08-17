const std = @import("std");

pub const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("ckzg.h");
});

pub const BYTES_PER_COMMITMENT: usize = c.BYTES_PER_COMMITMENT;
pub const BYTES_PER_PROOF: usize = c.BYTES_PER_PROOF;
pub const BYTES_PER_FIELD_ELEMENT: usize = c.BYTES_PER_FIELD_ELEMENT;
pub const FIELD_ELEMENTS_PER_BLOB: usize = c.FIELD_ELEMENTS_PER_BLOB;
pub const BYTES_PER_BLOB: usize = c.BYTES_PER_BLOB;
pub const FIELD_ELEMENTS_PER_EXT_BLOB: usize = c.FIELD_ELEMENTS_PER_EXT_BLOB;
pub const FIELD_ELEMENTS_PER_CELL: usize = c.FIELD_ELEMENTS_PER_CELL;
pub const BYTES_PER_CELL: usize = c.BYTES_PER_CELL;
pub const CELLS_PER_EXT_BLOB: usize = c.CELLS_PER_EXT_BLOB;

pub const Bytes32 = c.Bytes32;
pub const Bytes48 = c.Bytes48;
pub const Blob = c.Blob;
pub const Cell = c.Cell;
pub const KzgCommitment = c.KZGCommitment;
pub const KzgProof = c.KZGProof;

pub const Error = error{
    BadArgs,
    Internal,
    OutOfMemory,
    FileOpenFailed,
    LengthMismatch,
    NotInitialized,
};

pub const ProofAndY = struct {
    proof: KzgProof,
    y: Bytes32,
};

pub const Settings = struct {
    inner: c.KZGSettings = undefined,
    loaded: bool = false,

    pub fn loadTrustedSetup(
        g1_monomial_bytes: []const u8,
        g1_lagrange_bytes: []const u8,
        g2_monomial_bytes: []const u8,
        precompute: u64,
    ) !Settings {
        var settings = Settings{};
        try checkRet(c.load_trusted_setup(
            &settings.inner,
            sliceConstPtr(u8, g1_monomial_bytes),
            g1_monomial_bytes.len,
            sliceConstPtr(u8, g1_lagrange_bytes),
            g1_lagrange_bytes.len,
            sliceConstPtr(u8, g2_monomial_bytes),
            g2_monomial_bytes.len,
            precompute,
        ));
        settings.loaded = true;
        return settings;
    }

    pub fn loadTrustedSetupFile(path: [:0]const u8, precompute: u64) !Settings {
        var settings = Settings{};

        const file = c.fopen(path.ptr, "r");
        if (file == null) return error.FileOpenFailed;
        defer _ = c.fclose(file);

        try checkRet(c.load_trusted_setup_file(&settings.inner, file, precompute));
        settings.loaded = true;
        return settings;
    }

    pub fn deinit(self: *Settings) void {
        if (!self.loaded) return;
        c.free_trusted_setup(&self.inner);
        self.loaded = false;
    }

    pub fn blobToKzgCommitment(self: *const Settings, blob: *const Blob) !KzgCommitment {
        try self.ensureLoaded();

        var out: KzgCommitment = undefined;
        try checkRet(c.blob_to_kzg_commitment(&out, blob, &self.inner));
        return out;
    }

    pub fn computeKzgProof(
        self: *const Settings,
        blob: *const Blob,
        z_bytes: *const Bytes32,
    ) !ProofAndY {
        try self.ensureLoaded();

        var proof: KzgProof = undefined;
        var y: Bytes32 = undefined;
        try checkRet(c.compute_kzg_proof(&proof, &y, blob, z_bytes, &self.inner));
        return .{ .proof = proof, .y = y };
    }

    pub fn computeBlobKzgProof(
        self: *const Settings,
        blob: *const Blob,
        commitment_bytes: *const Bytes48,
    ) !KzgProof {
        try self.ensureLoaded();

        var out: KzgProof = undefined;
        try checkRet(c.compute_blob_kzg_proof(&out, blob, commitment_bytes, &self.inner));
        return out;
    }

    pub fn verifyKzgProof(
        self: *const Settings,
        commitment_bytes: *const Bytes48,
        z_bytes: *const Bytes32,
        y_bytes: *const Bytes32,
        proof_bytes: *const Bytes48,
    ) !bool {
        try self.ensureLoaded();
        var ok = false;
        try checkRet(c.verify_kzg_proof(
            &ok,
            commitment_bytes,
            z_bytes,
            y_bytes,
            proof_bytes,
            &self.inner,
        ));
        return ok;
    }

    pub fn verifyBlobKzgProof(
        self: *const Settings,
        blob: *const Blob,
        commitment_bytes: *const Bytes48,
        proof_bytes: *const Bytes48,
    ) !bool {
        try self.ensureLoaded();
        var ok = false;
        try checkRet(c.verify_blob_kzg_proof(&ok, blob, commitment_bytes, proof_bytes, &self.inner));
        return ok;
    }

    pub fn verifyBlobKzgProofBatch(
        self: *const Settings,
        blobs: []const Blob,
        commitments_bytes: []const Bytes48,
        proofs_bytes: []const Bytes48,
    ) !bool {
        try self.ensureLoaded();
        if (blobs.len != commitments_bytes.len or blobs.len != proofs_bytes.len) {
            return error.LengthMismatch;
        }

        var ok = false;
        try checkRet(c.verify_blob_kzg_proof_batch(
            &ok,
            sliceConstPtr(Blob, blobs),
            sliceConstPtr(Bytes48, commitments_bytes),
            sliceConstPtr(Bytes48, proofs_bytes),
            blobs.len,
            &self.inner,
        ));
        return ok;
    }

    pub fn computeCells(
        self: *const Settings,
        cells: *[CELLS_PER_EXT_BLOB]Cell,
        blob: *const Blob,
    ) !void {
        try self.ensureLoaded();
        try checkRet(c.compute_cells_and_kzg_proofs(
            cells,
            null,
            blob,
            &self.inner,
        ));
    }

    pub fn computeCellsAndKzgProofs(
        self: *const Settings,
        cells: *[CELLS_PER_EXT_BLOB]Cell,
        proofs: *[CELLS_PER_EXT_BLOB]KzgProof,
        blob: *const Blob,
    ) !void {
        try self.ensureLoaded();
        try checkRet(c.compute_cells_and_kzg_proofs(
            cells,
            proofs,
            blob,
            &self.inner,
        ));
    }

    pub fn recoverCells(
        self: *const Settings,
        recovered_cells: *[CELLS_PER_EXT_BLOB]Cell,
        cell_indices: []const u64,
        cells: []const Cell,
    ) !void {
        try self.ensureLoaded();
        if (cell_indices.len != cells.len) return error.LengthMismatch;

        try checkRet(c.recover_cells_and_kzg_proofs(
            recovered_cells,
            null,
            sliceConstPtr(u64, cell_indices),
            sliceConstPtr(Cell, cells),
            cell_indices.len,
            &self.inner,
        ));
    }

    pub fn recoverCellsAndKzgProofs(
        self: *const Settings,
        recovered_cells: *[CELLS_PER_EXT_BLOB]Cell,
        recovered_proofs: *[CELLS_PER_EXT_BLOB]KzgProof,
        cell_indices: []const u64,
        cells: []const Cell,
    ) !void {
        try self.ensureLoaded();
        if (cell_indices.len != cells.len) return error.LengthMismatch;

        try checkRet(c.recover_cells_and_kzg_proofs(
            recovered_cells,
            recovered_proofs,
            sliceConstPtr(u64, cell_indices),
            sliceConstPtr(Cell, cells),
            cell_indices.len,
            &self.inner,
        ));
    }

    pub fn verifyCellKzgProofBatch(
        self: *const Settings,
        commitments_bytes: []const Bytes48,
        cell_indices: []const u64,
        cells: []const Cell,
        proofs_bytes: []const Bytes48,
    ) !bool {
        try self.ensureLoaded();
        if (commitments_bytes.len != cell_indices.len or
            commitments_bytes.len != cells.len or
            commitments_bytes.len != proofs_bytes.len)
        {
            return error.LengthMismatch;
        }

        var ok = false;
        try checkRet(c.verify_cell_kzg_proof_batch(
            &ok,
            sliceConstPtr(Bytes48, commitments_bytes),
            sliceConstPtr(u64, cell_indices),
            sliceConstPtr(Cell, cells),
            sliceConstPtr(Bytes48, proofs_bytes),
            commitments_bytes.len,
            &self.inner,
        ));
        return ok;
    }

    fn ensureLoaded(self: *const Settings) !void {
        if (!self.loaded) return error.NotInitialized;
    }
};

fn checkRet(ret: c.C_KZG_RET) !void {
    switch (ret) {
        c.C_KZG_OK => {},
        c.C_KZG_BADARGS => return error.BadArgs,
        c.C_KZG_ERROR => return error.Internal,
        c.C_KZG_MALLOC => return error.OutOfMemory,
        else => return error.Internal,
    }
}

fn sliceConstPtr(comptime T: type, slice: []const T) [*c]const T {
    return if (slice.len == 0) null else slice.ptr;
}

fn sliceMutPtr(comptime T: type, slice: []T) [*c]T {
    return if (slice.len == 0) null else slice.ptr;
}
