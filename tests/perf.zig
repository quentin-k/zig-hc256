const std = @import("std");
const hc256 = @import("hc256");
const c_clockcycle = @intToFloat(f64, std.time.ns_per_us);

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ts_begin: i128 = undefined;
    var ts_end: i128 = undefined;

    var key: [32]u8 = undefined;
    var iv: [32]u8 = undefined;

    var page_32mb = try allocator.alloc(u8, 32 * 1024 * 1024);
    defer allocator.free(page_32mb);

    try std.os.getrandom(&key);
    try std.os.getrandom(&iv);

    ts_begin = std.time.nanoTimestamp();
    var c32k = hc256.Hc256.init(key, iv);
    ts_end = std.time.nanoTimestamp();

    const init_time = ts_end - ts_begin;
    try stdout.print(
        \\Initialization time:
        \\{}ns
        \\{d} clock cycles
        \\
    , .{ init_time, clockCycles(init_time, 1) });

    ts_begin = std.time.nanoTimestamp();
    c32k.applyStream(page_32mb);
    ts_end = std.time.nanoTimestamp();

    const cycles_per_byte = clockCycles(ts_end - ts_begin, page_32mb.len);
    try stdout.print(
        \\It took {}ns to apply the stream on a 32 megabyte page
        \\Cycles per byte: {d:>.3}
        \\Cycles per bit: {d:>.3}
        \\
    , .{ ts_end - ts_begin, cycles_per_byte, cycles_per_byte * 8.0 });
}

fn clockCycles(nanoseconds: i128, bytes: usize) f64 {
    const ns_f64 = @intToFloat(f64, nanoseconds);
    const clocks = ns_f64 / c_clockcycle;
    const b_f64 = @intToFloat(f64, bytes);
    const clocks_per_byte = clocks / b_f64;
    return clocks_per_byte;
}
