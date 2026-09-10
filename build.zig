const std = @import("std");
const builtin = @import("builtin");

// The pinned compiler lives in .zigversion and nowhere else; a build with any
// other version fails closed here, so the toolchain question has one answer.
const pinned_zig = std.mem.trim(u8, @embedFile(".zigversion"), " \t\r\n");

const c_flags = &[_][]const u8{ "-std=c11", "-Wall", "-Wextra", "-Werror" };

fn coreFor(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path("core/veil.zig"), .target = target, .optimize = optimize });
}

/// A root under abi/ or conformance/ that reaches the core as `@import("gossveil")`.
fn rootFor(b: *std.Build, source: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, libc: bool) *std.Build.Module {
    const m = b.createModule(.{
        .root_source_file = b.path(source),
        .target = target,
        .optimize = optimize,
        .link_libc = if (libc) true else null,
    });
    m.addImport("gossveil", coreFor(b, target, optimize));
    return m;
}

fn installInto(b: *std.Build, artifact: *std.Build.Step.Compile, dir: []const u8) *std.Build.Step {
    return &b.addInstallArtifact(artifact, .{ .dest_dir = .{ .override = .{ .custom = dir } } }).step;
}

pub fn build(b: *std.Build) void {
    if (!std.mem.eql(u8, builtin.zig_version_string, pinned_zig)) {
        std.debug.print("gossveil pins zig {s} in .zigversion; this is zig {s}. Run tools/toolchain-sync.\n", .{ pinned_zig, builtin.zig_version_string });
        std.process.exit(1);
    }
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core = b.addModule("gossveil", .{
        .root_source_file = b.path("core/veil.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(b.addLibrary(.{ .name = "gossveil", .root_module = coreFor(b, target, optimize), .linkage = .static }));

    const abi_shared = b.addLibrary(.{ .name = "gossveil_ffi", .root_module = rootFor(b, "abi/gossveil.zig", target, optimize, false), .linkage = .dynamic });
    b.installArtifact(abi_shared);
    const abi_static = b.addLibrary(.{ .name = "gossveil_ffi_static", .root_module = rootFor(b, "abi/gossveil.zig", target, optimize, false), .linkage = .static });
    b.installArtifact(abi_static);
    b.installFile("include/gossveil.h", "include/gossveil.h");

    const c_example = b.addExecutable(.{
        .name = "gossveil-example",
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }),
    });
    c_example.root_module.addCSourceFile(.{ .file = b.path("examples/c/main.c"), .flags = c_flags });
    c_example.root_module.addIncludePath(b.path("include"));
    c_example.root_module.linkLibrary(abi_static);
    const run_c_example = b.addRunArtifact(c_example);
    run_c_example.expectStdOutEqual("ok\n");
    b.step("c-example", "Build and run the C example against the static library").dependOn(&run_c_example.step);

    const apple_step = b.step("apple", "Build the iOS device, iOS simulator and macOS static libraries");
    const apple_slices = [_]struct { dir: []const u8, query: std.Target.Query }{
        .{ .dir = "ios", .query = .{ .cpu_arch = .aarch64, .os_tag = .ios } },
        .{ .dir = "ios-simulator", .query = .{ .cpu_arch = .aarch64, .os_tag = .ios, .abi = .simulator } },
        .{ .dir = "ios-simulator-x86_64", .query = .{ .cpu_arch = .x86_64, .os_tag = .ios, .abi = .simulator } },
        .{ .dir = "macos", .query = .{ .cpu_arch = .aarch64, .os_tag = .macos } },
        .{ .dir = "macos-x86_64", .query = .{ .cpu_arch = .x86_64, .os_tag = .macos } },
    };
    for (apple_slices) |slice| {
        const slice_target = b.resolveTargetQuery(slice.query);
        const lib = b.addLibrary(.{ .name = "gossveil_ffi_static", .root_module = rootFor(b, "abi/gossveil.zig", slice_target, optimize, false), .linkage = .static });
        apple_step.dependOn(installInto(b, lib, slice.dir));
    }

    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm = b.addExecutable(.{ .name = "gossveil", .root_module = rootFor(b, "abi/wasm.zig", wasm_target, optimize, false) });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    wasm.root_module.strip = true;
    b.step("wasm", "Build the wasm32 core for the web package").dependOn(installInto(b, wasm, "wasm"));

    const java_home = b.option([]const u8, "java-home", "JDK root holding include/jni.h (default: $JAVA_HOME)") orelse
        b.graph.environ_map.get("JAVA_HOME");
    const jni_step = b.step("jni", "Build the JNI shared library for the host JVM");
    if (java_home) |root| {
        const jni = b.addLibrary(.{ .name = "gossveil_jni", .root_module = rootFor(b, "abi/jni.zig", target, optimize, true), .linkage = .dynamic });
        jni.root_module.strip = optimize != .Debug;
        jni.root_module.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ root, "include" }) });
        const platform = switch (target.result.os.tag) {
            .macos => "darwin",
            .windows => "win32",
            else => "linux",
        };
        jni.root_module.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ root, "include", platform }) });
        jni_step.dependOn(installInto(b, jni, "jni"));
    } else {
        jni_step.dependOn(&b.addFail("the jni step needs -Djava-home=<jdk> or JAVA_HOME").step);
    }

    const ndk = b.option([]const u8, "ndk", "Android NDK root (default: $ANDROID_NDK_HOME)") orelse
        b.graph.environ_map.get("ANDROID_NDK_HOME");
    const android_step = b.step("android", "Build the JNI shared library for arm64-v8a and x86_64");
    if (ndk) |root| {
        const host_tag = switch (builtin.os.tag) {
            .macos => "darwin-x86_64",
            .windows => "windows-x86_64",
            else => "linux-x86_64",
        };
        const sysroot_include = b.pathJoin(&.{ root, "toolchains", "llvm", "prebuilt", host_tag, "sysroot", "usr", "include" });
        const abis = [_]struct { dir: []const u8, arch: std.Target.Cpu.Arch }{
            .{ .dir = "arm64-v8a", .arch = .aarch64 },
            .{ .dir = "x86_64", .arch = .x86_64 },
        };
        for (abis) |abi| {
            const abi_target = b.resolveTargetQuery(.{ .cpu_arch = abi.arch, .os_tag = .linux, .abi = .android });
            const lib = b.addLibrary(.{ .name = "gossveil_jni", .root_module = rootFor(b, "abi/jni.zig", abi_target, optimize, false), .linkage = .dynamic });
            lib.root_module.strip = optimize != .Debug;
            lib.root_module.addIncludePath(.{ .cwd_relative = sysroot_include });
            android_step.dependOn(installInto(b, lib, b.pathJoin(&.{ "android", abi.dir })));
        }
    } else {
        android_step.dependOn(&b.addFail("the android step needs -Dndk=<ndk root> or ANDROID_NDK_HOME").step);
    }

    const unit_tests = b.addTest(.{ .root_module = core });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    b.step("test", "Run every unit test").dependOn(&run_unit_tests.step);

    const conform = b.addExecutable(.{ .name = "conform", .root_module = rootFor(b, "conformance/conform.zig", target, optimize, false) });
    b.installArtifact(conform);
    b.step("conform", "Build the conformance command that answers one JSON operation per run").dependOn(&b.addInstallArtifact(conform, .{}).step);
    const replay = b.addRunArtifact(conform);
    replay.setCwd(b.path("."));
    replay.addArgs(&.{ "--replay", "conformance/vectors" });
    b.step("conformance", "Replay the frozen wire vectors through the core").dependOn(&replay.step);

    const gate = b.addExecutable(.{
        .name = "gate",
        .root_module = b.createModule(.{ .root_source_file = b.path("tools/gate.zig"), .target = b.graph.host, .optimize = .ReleaseSafe }),
    });
    const run_gate = b.addRunArtifact(gate);
    run_gate.setCwd(b.path("."));
    if (b.args) |args| run_gate.addArgs(args) else run_gate.addArg("--tree");
    b.step("gate", "Run the source gate (-- --staged | --tree | --commit-msg <file> | --log <range> | --diff <range> | --pr-body <file>)").dependOn(&run_gate.step);

    const gate_tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("tools/gate.zig"), .target = b.graph.host, .optimize = optimize }) });
    const ci_gate = b.addRunArtifact(gate);
    ci_gate.setCwd(b.path("."));
    ci_gate.addArg("--tree");

    const ci_step = b.step("ci", "Every gate locally: unit tests, the frozen vectors, the C example, the source gate and its tests");
    ci_step.dependOn(&run_unit_tests.step);
    ci_step.dependOn(&replay.step);
    ci_step.dependOn(&run_c_example.step);
    ci_step.dependOn(&b.addRunArtifact(gate_tests).step);
    ci_step.dependOn(&ci_gate.step);
}
