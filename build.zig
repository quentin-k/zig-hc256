const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("hc256", "hc256.zig");
    lib.setBuildMode(mode);
    lib.install();

    const test_vectors = b.addTest("tests/test-vectors.zig");
    test_vectors.setBuildMode(mode);
    test_vectors.addPackagePath("hc256", "hc256.zig");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&test_vectors.step);
}
