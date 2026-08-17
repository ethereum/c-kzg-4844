const std = @import("std");
const ckzg = @import("ckzg");
const trusted_setup = @import("trusted_setup");

fn loadSettings() !ckzg.Settings {
    return ckzg.Settings.loadTrustedSetup(
        trusted_setup.g1_monomial_bytes,
        trusted_setup.g1_lagrange_bytes,
        trusted_setup.g2_monomial_bytes,
        0,
    );
}

fn collectCases(io: std.Io, alloc: std.mem.Allocator, suite: []const u8) ![][]const u8 {
    const base = try std.fmt.allocPrint(alloc, "tests/{s}/kzg-mainnet", .{suite});

    var dir = try std.Io.Dir.cwd().openDir(io, base, .{ .iterate = true });
    defer dir.close(io);

    var paths: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        try paths.append(alloc, try std.fmt.allocPrint(alloc, "{s}/{s}/data.json", .{ base, entry.name }));
    }

    std.mem.sort([]const u8, paths.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    return paths.toOwnedSlice(alloc);
}

fn hexToStruct(comptime T: type, hex: []const u8) !T {
    var v: T = undefined;
    const s = if (std.mem.startsWith(u8, hex, "0x")) hex[2..] else hex;
    const decoded = try std.fmt.hexToBytes(&v.bytes, s);
    if (decoded.len != v.bytes.len) return error.InvalidLength;
    return v;
}

// EIP-4844

test "blob_to_kzg_commitment" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct { blob: []const u8 },
        output: ?[]const u8,
    };

    for (try collectCases(io, alloc, "blob_to_kzg_commitment")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        const result: anyerror!ckzg.KzgCommitment = blk: {
            const blob = hexToStruct(ckzg.Blob, tc.input.blob) catch |e| break :blk e;
            break :blk s.blobToKzgCommitment(&blob);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            const expected = try hexToStruct(ckzg.KzgCommitment, tc.output.?);
            try std.testing.expectEqualSlices(u8, &expected.bytes, &(try result).bytes);
        }
    }
}

test "compute_kzg_proof" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct { blob: []const u8, z: []const u8 },
        output: ?[2][]const u8, // [proof, y]
    };

    for (try collectCases(io, alloc, "compute_kzg_proof")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        const result: anyerror!ckzg.ProofAndY = blk: {
            const blob = hexToStruct(ckzg.Blob, tc.input.blob) catch |e| break :blk e;
            const z = hexToStruct(ckzg.Bytes32, tc.input.z) catch |e| break :blk e;
            break :blk s.computeKzgProof(&blob, &z);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            const pf = try result;
            try std.testing.expectEqualSlices(u8, &(try hexToStruct(ckzg.KzgProof, tc.output.?[0])).bytes, &pf.proof.bytes);
            try std.testing.expectEqualSlices(u8, &(try hexToStruct(ckzg.Bytes32, tc.output.?[1])).bytes, &pf.y.bytes);
        }
    }
}

test "compute_blob_kzg_proof" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct { blob: []const u8, commitment: []const u8 },
        output: ?[]const u8,
    };

    for (try collectCases(io, alloc, "compute_blob_kzg_proof")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        const result: anyerror!ckzg.KzgProof = blk: {
            const blob = hexToStruct(ckzg.Blob, tc.input.blob) catch |e| break :blk e;
            const commitment = hexToStruct(ckzg.Bytes48, tc.input.commitment) catch |e| break :blk e;
            break :blk s.computeBlobKzgProof(&blob, &commitment);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            const expected = try hexToStruct(ckzg.KzgProof, tc.output.?);
            try std.testing.expectEqualSlices(u8, &expected.bytes, &(try result).bytes);
        }
    }
}

test "verify_kzg_proof" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct {
            commitment: []const u8,
            z: []const u8,
            y: []const u8,
            proof: []const u8,
        },
        output: ?bool,
    };

    for (try collectCases(io, alloc, "verify_kzg_proof")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        const result: anyerror!bool = blk: {
            const commitment = hexToStruct(ckzg.Bytes48, tc.input.commitment) catch |e| break :blk e;
            const z = hexToStruct(ckzg.Bytes32, tc.input.z) catch |e| break :blk e;
            const y = hexToStruct(ckzg.Bytes32, tc.input.y) catch |e| break :blk e;
            const proof = hexToStruct(ckzg.Bytes48, tc.input.proof) catch |e| break :blk e;
            break :blk s.verifyKzgProof(&commitment, &z, &y, &proof);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            try std.testing.expectEqual(tc.output.?, try result);
        }
    }
}

test "verify_blob_kzg_proof" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct { blob: []const u8, commitment: []const u8, proof: []const u8 },
        output: ?bool,
    };

    for (try collectCases(io, alloc, "verify_blob_kzg_proof")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        const result: anyerror!bool = blk: {
            const blob = hexToStruct(ckzg.Blob, tc.input.blob) catch |e| break :blk e;
            const commitment = hexToStruct(ckzg.Bytes48, tc.input.commitment) catch |e| break :blk e;
            const proof = hexToStruct(ckzg.Bytes48, tc.input.proof) catch |e| break :blk e;
            break :blk s.verifyBlobKzgProof(&blob, &commitment, &proof);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            try std.testing.expectEqual(tc.output.?, try result);
        }
    }
}

test "verify_blob_kzg_proof_batch" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct {
            blobs: [][]const u8,
            commitments: [][]const u8,
            proofs: [][]const u8,
        },
        output: ?bool,
    };

    for (try collectCases(io, alloc, "verify_blob_kzg_proof_batch")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        const result: anyerror!bool = blk: {
            const blobs = try alloc.alloc(ckzg.Blob, tc.input.blobs.len);
            for (tc.input.blobs, blobs) |hex, *b| b.* = hexToStruct(ckzg.Blob, hex) catch |e| break :blk e;

            const commitments = try alloc.alloc(ckzg.Bytes48, tc.input.commitments.len);
            for (tc.input.commitments, commitments) |hex, *c| c.* = hexToStruct(ckzg.Bytes48, hex) catch |e| break :blk e;

            const proofs = try alloc.alloc(ckzg.Bytes48, tc.input.proofs.len);
            for (tc.input.proofs, proofs) |hex, *p| p.* = hexToStruct(ckzg.Bytes48, hex) catch |e| break :blk e;

            break :blk s.verifyBlobKzgProofBatch(blobs, commitments, proofs);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            try std.testing.expectEqual(tc.output.?, try result);
        }
    }
}

// EIP-7594

test "compute_cells" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct { blob: []const u8 },
        output: ?[][]const u8,
    };

    for (try collectCases(io, alloc, "compute_cells")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        var cells: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Cell = undefined;
        const result: anyerror!void = blk: {
            const blob = hexToStruct(ckzg.Blob, tc.input.blob) catch |e| break :blk e;
            break :blk s.computeCells(&cells, &blob);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            try result;
            for (tc.output.?, 0..) |hex, i| {
                try std.testing.expectEqualSlices(u8, &(try hexToStruct(ckzg.Cell, hex)).bytes, &cells[i].bytes);
            }
        }
    }
}

test "compute_cells_and_kzg_proofs" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct { blob: []const u8 },
        output: ?[2][][]const u8, // [cells[128], proofs[128]]
    };

    for (try collectCases(io, alloc, "compute_cells_and_kzg_proofs")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        var cells: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Cell = undefined;
        var proofs: [ckzg.CELLS_PER_EXT_BLOB]ckzg.KzgProof = undefined;
        const result: anyerror!void = blk: {
            const blob = hexToStruct(ckzg.Blob, tc.input.blob) catch |e| break :blk e;
            break :blk s.computeCellsAndKzgProofs(&cells, &proofs, &blob);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            try result;
            for (tc.output.?[0], 0..) |hex, i| {
                try std.testing.expectEqualSlices(u8, &(try hexToStruct(ckzg.Cell, hex)).bytes, &cells[i].bytes);
            }
            for (tc.output.?[1], 0..) |hex, i| {
                try std.testing.expectEqualSlices(u8, &(try hexToStruct(ckzg.KzgProof, hex)).bytes, &proofs[i].bytes);
            }
        }
    }
}

test "recover_cells" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct {
            cell_indices: []u64,
            cells: [][]const u8,
        },
        output: ?[2][][]const u8, // [recovered_cells[128], recovered_proofs[128]]
    };

    for (try collectCases(io, alloc, "recover_cells_and_kzg_proofs")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        var recovered_cells: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Cell = undefined;
        const result: anyerror!void = blk: {
            const input_cells = try alloc.alloc(ckzg.Cell, tc.input.cells.len);
            for (tc.input.cells, input_cells) |hex, *c| c.* = hexToStruct(ckzg.Cell, hex) catch |e| break :blk e;
            break :blk s.recoverCells(&recovered_cells, tc.input.cell_indices, input_cells);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            try result;
            for (tc.output.?[0], 0..) |hex, i| {
                try std.testing.expectEqualSlices(u8, &(try hexToStruct(ckzg.Cell, hex)).bytes, &recovered_cells[i].bytes);
            }
        }
    }
}

test "recover_cells_and_kzg_proofs" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct {
            cell_indices: []u64,
            cells: [][]const u8,
        },
        output: ?[2][][]const u8, // [recovered_cells[128], recovered_proofs[128]]
    };

    for (try collectCases(io, alloc, "recover_cells_and_kzg_proofs")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        var recovered_cells: [ckzg.CELLS_PER_EXT_BLOB]ckzg.Cell = undefined;
        var recovered_proofs: [ckzg.CELLS_PER_EXT_BLOB]ckzg.KzgProof = undefined;
        const result: anyerror!void = blk: {
            const input_cells = try alloc.alloc(ckzg.Cell, tc.input.cells.len);
            for (tc.input.cells, input_cells) |hex, *c| c.* = hexToStruct(ckzg.Cell, hex) catch |e| break :blk e;
            break :blk s.recoverCellsAndKzgProofs(&recovered_cells, &recovered_proofs, tc.input.cell_indices, input_cells);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            try result;
            for (tc.output.?[0], 0..) |hex, i| {
                try std.testing.expectEqualSlices(u8, &(try hexToStruct(ckzg.Cell, hex)).bytes, &recovered_cells[i].bytes);
            }
            for (tc.output.?[1], 0..) |hex, i| {
                try std.testing.expectEqualSlices(u8, &(try hexToStruct(ckzg.KzgProof, hex)).bytes, &recovered_proofs[i].bytes);
            }
        }
    }
}

test "verify_cell_kzg_proof_batch" {
    var s = try loadSettings();
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = std.testing.io;

    const Test = struct {
        input: struct {
            commitments: [][]const u8,
            cell_indices: []u64,
            cells: [][]const u8,
            proofs: [][]const u8,
        },
        output: ?bool,
    };

    for (try collectCases(io, alloc, "verify_cell_kzg_proof_batch")) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
        const tc = (try std.json.parseFromSlice(Test, alloc, text, .{})).value;
        const result: anyerror!bool = blk: {
            const commitments = try alloc.alloc(ckzg.Bytes48, tc.input.commitments.len);
            for (tc.input.commitments, commitments) |hex, *c| c.* = hexToStruct(ckzg.Bytes48, hex) catch |e| break :blk e;

            const cells = try alloc.alloc(ckzg.Cell, tc.input.cells.len);
            for (tc.input.cells, cells) |hex, *c| c.* = hexToStruct(ckzg.Cell, hex) catch |e| break :blk e;

            const proofs = try alloc.alloc(ckzg.Bytes48, tc.input.proofs.len);
            for (tc.input.proofs, proofs) |hex, *p| p.* = hexToStruct(ckzg.Bytes48, hex) catch |e| break :blk e;

            break :blk s.verifyCellKzgProofBatch(commitments, tc.input.cell_indices, cells, proofs);
        };
        if (tc.output == null) {
            if (result) |_| return error.TestExpectedError else |_| {}
        } else {
            try std.testing.expectEqual(tc.output.?, try result);
        }
    }
}
