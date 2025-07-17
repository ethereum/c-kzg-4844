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

    if (!has_blst_submodule) {
        // Try to initialize submodules automatically
        std.log.info("blst submodule not found, attempting to initialize...", .{});
        
        // Use std.process to run git submodule command synchronously at build time
        var child = std.process.Child.init(&[_][]const u8{ "git", "submodule", "update", "--init", "--recursive" }, std.heap.page_allocator);
        child.cwd_dir = std.fs.cwd();
        const term = child.spawnAndWait() catch {
            std.log.err("Failed to run git submodule command", .{});
            std.log.err("Please run manually: git submodule update --init --recursive", .{});
            std.process.exit(1);
        };
        
        if (term != .Exited or term.Exited != 0) {
            std.log.err("git submodule command failed with exit code", .{});
            std.log.err("Please run manually: git submodule update --init --recursive", .{});
            std.process.exit(1);
        }
        
        // Check again after attempting to initialize
        const file = std.fs.cwd().openFile("blst/src/server.c", .{}) catch {
            std.log.err("blst submodule still not available after git submodule init", .{});
            std.log.err("Please ensure you're in a git repository and have git access", .{});
            std.process.exit(1);
        };
        file.close();
        std.log.info("Successfully initialized submodules", .{});
    }

    // Build blst library from source
    const blst_lib = b.addStaticLibrary(.{
        .name = "blst",
        .target = target,
        .optimize = optimize,
    });
    
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
    
    // Link with our built blst library
    lib.linkLibrary(blst_lib);
    
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
