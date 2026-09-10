const std = @import("std");
const builtin = @import("builtin");

// The pinned compiler lives in .zigversion and nowhere else; a build with any
// other version fails closed here, so the toolchain question has one answer.
const pinned_zig = std.mem.trim(u8, @embedFile(".zigversion"), " \t\r\n");

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

    const static_lib = b.addLibrary(.{
        .name = "gossveil",
        .root_module = b.createModule(.{
            .root_source_file = b.path("core/veil.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });
    b.installArtifact(static_lib);

    const unit_tests = b.addTest(.{ .root_module = core });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run every unit test");
    test_step.dependOn(&run_unit_tests.step);

    const gate = b.addExecutable(.{
        .name = "gate",
        .root_module = b.createModule(.{ .root_source_file = b.path("tools/gate.zig"), .target = b.graph.host, .optimize = .ReleaseSafe }),
    });
    const run_gate = b.addRunArtifact(gate);
    run_gate.setCwd(b.path("."));
    if (b.args) |args| run_gate.addArgs(args) else run_gate.addArg("--tree");
    const gate_step = b.step("gate", "Run the source gate (-- --staged | --tree | --commit-msg <file> | --log <range> | --diff <range> | --pr-body <file>)");
    gate_step.dependOn(&run_gate.step);

    const gate_tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("tools/gate.zig"), .target = b.graph.host, .optimize = optimize }) });

    const ci_step = b.step("ci", "Every gate locally: unit tests, the source gate, the gate's own tests");
    ci_step.dependOn(&run_unit_tests.step);
    ci_step.dependOn(&b.addRunArtifact(gate_tests).step);
    const ci_gate = b.addRunArtifact(gate);
    ci_gate.setCwd(b.path("."));
    ci_gate.addArg("--tree");
    ci_step.dependOn(&ci_gate.step);
}
