const std = @import("std");
const hc256 = @import("hc256");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var b: [1]u8 = undefined;
    try std.os.getrandom(&b);
    if (b[0] % 2 == 0) {
        try stdout.print("--- FAST ---\n", .{});
        try fast(stdout);
        try stdout.print("--- SAFE ---\n", .{});
        try safe(stdout);
    } else {
        try stdout.print("--- SAFE ---\n", .{});
        try safe(stdout);
        try stdout.print("--- FAST ---\n", .{});
        try fast(stdout);
    }
}

fn fast(writer: anytype) !void {
    var slowest: u64 = 0;
    var fastest: u64 = std.math.maxInt(u64);
    var totals: f64 = 0.0;

    var cipher = hc256.Hc256.init([_]u8{0} ** 32, [_]u8{0} ** 32);
    var buffer = [_]u8{0} ** hc256.buffer_size;

    var i: usize = 0;
    var timer = try std.time.Timer.start();
    var iterations: usize = 10;
    while (iterations <= 1_000_000) : (iterations *= 10) {
        while (i < iterations) : (i += 1) {
            timer.reset();
            _ = cipher.applyStreamFast(&buffer);
            const elapsed = timer.read();
            totals += @intToFloat(f64, elapsed);
            fastest = @minimum(fastest, elapsed);
            slowest = @maximum(slowest, elapsed);
        }
        try writer.print(
            \\
            \\Iterations: {}
            \\Fastest: {}ns
            \\Slowest: {}ns
            \\Average: {d:>.3}ns
            \\Buffer: {}
            \\
        , .{
            iterations,
            fastest,
            slowest,
            totals / @intToFloat(f64, iterations),
            std.fmt.fmtSliceHexLower(&buffer),
        });
    }
}

fn safe(writer: anytype) !void {
    var slowest: u64 = 0;
    var fastest: u64 = std.math.maxInt(u64);
    var totals: f64 = 0.0;

    var cipher = hc256.Hc256.init([_]u8{0} ** 32, [_]u8{0} ** 32);
    var buffer = [_]u8{0} ** hc256.buffer_size;

    var i: usize = 0;
    var timer = try std.time.Timer.start();
    var iterations: usize = 10;
    while (iterations <= 1_000_000) : (iterations *= 10) {
        while (i < iterations) : (i += 1) {
            timer.reset();
            cipher.applyStream(&buffer);
            const elapsed = timer.read();
            totals += @intToFloat(f64, elapsed);
            fastest = @minimum(fastest, elapsed);
            slowest = @maximum(slowest, elapsed);
        }
        try writer.print(
            \\
            \\Iterations: {}
            \\Fastest: {}ns
            \\Slowest: {}ns
            \\Average: {d:>.3}ns
            \\Buffer: {}
            \\
        , .{
            iterations,
            fastest,
            slowest,
            totals / @intToFloat(f64, iterations),
            std.fmt.fmtSliceHexLower(&buffer),
        });
    }
}
