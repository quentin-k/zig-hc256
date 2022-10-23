const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("hc256", "hc256.zig");
    lib.setBuildMode(mode);
    lib.install();

    const target = b.standardTargetOptions(.{});

    const measure_speed = b.addExecutable("measure_speed", "tests/measure_speed.zig");
    measure_speed.addPackagePath("hc256", "hc256.zig");
    measure_speed.setTarget(target);
    measure_speed.setBuildMode(mode);
    measure_speed.install();

    const gw_speed = b.addExecutable("gw_speed", "tests/gw_speed.zig");
    gw_speed.addPackagePath("hc256", "hc256.zig");
    gw_speed.setTarget(target);
    gw_speed.setBuildMode(mode);
    gw_speed.install();

    const apply_speed = b.addExecutable("apply_speed", "tests/apply_speed.zig");
    apply_speed.addPackagePath("hc256", "hc256.zig");
    apply_speed.setTarget(target);
    apply_speed.setBuildMode(mode);
    apply_speed.install();


    const test_vectors = b.addTest("tests/test-vectors.zig");
    test_vectors.setBuildMode(mode);
    test_vectors.addPackagePath("hc256", "hc256.zig");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&test_vectors.step);
}
