const std = @import("std");
const hc256 = @import("hc256");
const iterations = 0x4000000 * 2;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var cipher = hc256.Hc256.init([_]u8{0} ** 32, [_]u8{0} ** 32);
    var i: usize = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) cipher.genWords();
    var ns_elapsed = timer.read();
    try stdout.print(
        "Time to run genWords: {d:>.4}s\nwords: {}\n",
        .{
            @intToFloat(f64, ns_elapsed) / @intToFloat(f64, std.time.ns_per_s),
            std.fmt.fmtSliceHexLower(&cipher.buffer),
        },
    );
}
