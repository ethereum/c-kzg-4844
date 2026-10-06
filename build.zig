const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const blst = b.dependency("blst", .{});

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.addWriteFiles().add("c.h",
            \\#include <stdio.h>
            \\#include "ckzg.h"
            \\
        ),
        .target = target,
        .optimize = optimize,
    });
    translate_c.addIncludePath(b.path("src"));
    translate_c.addIncludePath(blst.path("bindings"));

    const ckzg_module = b.addModule("ckzg", .{
        .root_source_file = b.path("bindings/zig/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "c", .module = translate_c.createModule() },
        },
    });
    ckzg_module.addIncludePath(b.path("src"));

    const lib = b.addLibrary(.{
        .name = "ckzg",
        .linkage = .static,
        .root_module = ckzg_module,
    });
    lib.root_module.link_libc = true;
    lib.root_module.addIncludePath(b.path("src"));
    lib.root_module.addIncludePath(blst.path("bindings"));

    const blst_flags: []const []const u8 = &.{ "-O2", "-ffreestanding", "-D__BLST_PORTABLE__" };
    switch (target.result.cpu.arch) {
        .aarch64, .x86_64 => {
            lib.root_module.addCSourceFiles(.{
                .root = blst.path("."),
                .files = &.{"src/server.c"},
                .flags = blst_flags,
            });
            lib.root_module.addCSourceFiles(.{
                .root = b.path("."),
                .files = &.{"src/ckzg.c"},
                .flags = blst_flags,
            });
            lib.root_module.addCSourceFile(.{
                .file = blst.path("build/assembly.S"),
                .flags = blst_flags,
            });
        },
        else => {
            const no_asm_flags: []const []const u8 = &.{ "-O2", "-ffreestanding", "-D__BLST_PORTABLE__", "-D__BLST_NO_ASM__" };
            lib.root_module.addCSourceFiles(.{
                .root = blst.path("."),
                .files = &.{"src/server.c"},
                .flags = no_asm_flags,
            });
            lib.root_module.addCSourceFiles(.{
                .root = b.path("."),
                .files = &.{"src/ckzg.c"},
                .flags = no_asm_flags,
            });
        },
    }

    b.installArtifact(lib);

    const trusted_setup_mod = buildTrustedSetupModule(b, "src/trusted_setup.txt");

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("bindings/zig/src/tests.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "ckzg", .module = ckzg_module },
                .{ .name = "trusted_setup", .module = trusted_setup_mod },
            },
        }),
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run Zig binding tests");
    test_step.dependOn(&run_tests.step);
}

fn buildTrustedSetupModule(b: *std.Build, sub_path: []const u8) *std.Build.Module {
    b.dependOnFileContents(b.path(sub_path));
    const path = b.root.joinString(b.allocator, sub_path) catch @panic("OOM");
    const text = std.Io.Dir.cwd().readFileAlloc(b.graph.io, path, b.allocator, .unlimited) catch |e|
        std.debug.panic("cannot read trusted setup '{s}': {s}", .{ path, @errorName(e) });

    var it = std.mem.tokenizeAny(u8, text, " \t\r\n");

    const n_g1 = parseUsize(&it) orelse std.debug.panic("trusted setup missing g1 count", .{});
    const n_g2 = parseUsize(&it) orelse std.debug.panic("trusted setup missing g2 count", .{});

    const wf = b.addWriteFiles();
    _ = wf.add("g1_lagrange.bin", decodeHexPoints(b.allocator, &it, n_g1, 48));
    _ = wf.add("g2_monomial.bin", decodeHexPoints(b.allocator, &it, n_g2, 96));
    _ = wf.add("g1_monomial.bin", decodeHexPoints(b.allocator, &it, n_g1, 48));

    const src = wf.add("trusted_setup.zig", b.fmt(
        \\// Generated from src/trusted_setup.txt at build time.
        \\pub const num_g1_points: usize = {d};
        \\pub const num_g2_points: usize = {d};
        \\pub const g1_lagrange_bytes = @embedFile("g1_lagrange.bin")[0 .. num_g1_points * 48];
        \\pub const g2_monomial_bytes = @embedFile("g2_monomial.bin")[0 .. num_g2_points * 96];
        \\pub const g1_monomial_bytes = @embedFile("g1_monomial.bin")[0 .. num_g1_points * 48];
        \\
    , .{ n_g1, n_g2 }));

    return b.addModule("trusted_setup", .{ .root_source_file = src });
}

fn parseUsize(it: anytype) ?usize {
    const token = it.next() orelse return null;
    return std.fmt.parseUnsigned(usize, token, 10) catch null;
}

fn decodeHexPoints(alloc: std.mem.Allocator, it: anytype, count: usize, comptime point_size: usize) []const u8 {
    const out = alloc.alloc(u8, count * point_size) catch @panic("OOM");
    for (0..count) |i| {
        const hex = it.next() orelse std.debug.panic("trusted setup truncated at point {d}", .{i});
        if (hex.len != point_size * 2) std.debug.panic("point {d} has wrong hex length: {d}", .{ i, hex.len });
        _ = std.fmt.hexToBytes(out[i * point_size ..][0..point_size], hex) catch
            std.debug.panic("invalid hex at point {d}", .{i});
    }
    return out;
}
