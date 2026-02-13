const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("bindings/zig/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib_mod.addIncludePath(b.path("src"));
    lib_mod.addIncludePath(b.path("blst/bindings"));

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "c_kzg_4844",
        .root_module = lib_mod,
    });

    // Check if blst submodule is available
    const has_blst_submodule = blk: {
        const file = std.fs.cwd().openFile("blst/src/server.c", .{}) catch break :blk false;
        file.close();
        break :blk true;
    };

    var server_cmd: ?*std.Build.Step.Run = null;
    
    if (!has_blst_submodule) {
        // Download blst at build time for zig fetch
        std.log.info("Downloading blst library...", .{});
        
        const mkdir_cmd = b.addSystemCommand(&[_][]const u8{ "mkdir", "-p", "blst" });
        
        const download_cmd = b.addSystemCommand(&[_][]const u8{
            "curl", "-L", "-o", "blst.tar.gz",
            "https://github.com/supranational/blst/archive/v0.3.15.tar.gz"
        });
        download_cmd.step.dependOn(&mkdir_cmd.step);
        
        const extract_cmd = b.addSystemCommand(&[_][]const u8{
            "tar", "xzf", "blst.tar.gz", "--strip-components=1", "-C", "blst"
        });
        extract_cmd.step.dependOn(&download_cmd.step);
        
        // Create server.c unity build file
        server_cmd = b.addSystemCommand(&[_][]const u8{
            "sh", "-c", 
            \\cat > blst/src/server.c << 'EOF'
            \\#include "keygen.c"
            \\#include "hash_to_field.c"
            \\#include "e1.c"
            \\#include "map_to_g1.c"
            \\#include "e2.c"
            \\#include "map_to_g2.c"
            \\#include "fp12_tower.c"
            \\#include "pairing.c"
            \\#include "aggregate.c"
            \\#include "exp.c"
            \\#include "sqrt.c"
            \\#include "recip.c"
            \\#include "bulk_addition.c"
            \\#include "multi_scalar.c"
            \\#include "consts.c"
            \\#include "vect.c"
            \\#include "exports.c"
            \\#ifndef __BLST_CGO__
            \\# include "rb_tree.c"
            \\#endif
            \\#ifdef BLST_FR_PENTAROOT
            \\# include "pentaroot.c"
            \\#endif
            \\#ifndef __BLST_NO_CPUID__
            \\# include "cpuid.c"
            \\#endif
            \\EOF
        });
        server_cmd.?.step.dependOn(&extract_cmd.step);
    }

    // Build blst library from source
    const blst_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
    });
    
    const blst_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "blst",
        .root_module = blst_mod,
    });
    
    // If we downloaded blst, make sure blst_lib waits for the download
    if (server_cmd) |cmd| {
        blst_lib.step.dependOn(&cmd.step);
    }
    
    blst_lib.addCSourceFile(.{
        .file = b.path("blst/src/server.c"),
        .flags = &[_][]const u8{
            "-std=c99",
            "-O3",
            "-fno-exceptions",
            "-D__BLST_PORTABLE__",
        },
    });
    
    blst_lib.addAssemblyFile(b.path("blst/build/assembly.S"));
    blst_lib.addIncludePath(b.path("blst/bindings"));
    blst_lib.linkLibC();
    
    // Link with our built blst library
    lib.linkLibrary(blst_lib);

    // Add C-KZG source files
    lib.addCSourceFile(.{
        .file = b.path("src/ckzg.c"),
        .flags = &[_][]const u8{
            "-std=c99",
            "-O3",
            "-fno-exceptions",
            "-DBLST_PORTABLE",
        },
    });
    
    lib.addIncludePath(b.path("src"));
    lib.addIncludePath(b.path("blst/bindings"));
    lib.linkLibC();

    b.installArtifact(lib);
    
    // Export module for external projects using this as a dependency
    _ = b.addModule("c_kzg_4844", .{
        .root_source_file = b.path("bindings/zig/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}