const std = @import("std");
const hc256 = @import("hc256");
const cycles_per_nanosecond = 3.2; // This is for a 3.2 GHz machine
const iterations = 0x4000000;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key: [32]u8 = [_]u8{0} ** 32;
    var iv: [32]u8 = [_]u8{0} ** 32;

    var msg: [64]u8 = [_]u8{0} ** 64;

    var timer = try std.time.Timer.start();
    var cipher = hc256.Hc256.init(key, iv);
    const init_time = timer.read();

    try stdout.print(
        \\Initialization time:
        \\{}ns
        \\{d} clock cycles
        \\
    , .{ init_time, @intToFloat(f64, init_time) / cycles_per_nanosecond });

    timer.reset();
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        _ = cipher.applyStreamFast(&msg);
        _ = cipher.applyStreamFast(&msg);
    }
    var elapsed = timer.read();

    const bytes_per_cycle = cyclesPerByte(elapsed, 64 * 2 * iterations);
    try stdout.print(
        \\It took {d:>.4}s for repeated encryption
        \\bytes per cycle: {d:>.4}
        \\message: {}
        \\
    , .{ @intToFloat(f64, elapsed) / @intToFloat(f64, std.time.ns_per_s), bytes_per_cycle, std.fmt.fmtSliceHexLower(&msg) });

    const stream_size = iterations * 2 * 64;
    var stream: []u8 = try allocator.alloc(u8, stream_size);
    defer allocator.free(stream);

    timer.reset();
    _ = cipher.applyStreamFast(stream);
    elapsed = timer.read();

    try stdout.print(
        \\It took {d:>.4}s to encrypted {} bytes of data
        \\bytes per cycle: {d:>.4}
        \\message[0..64]: {}
        \\
    , .{ @intToFloat(f64, elapsed) / @intToFloat(f64, std.time.ns_per_s),stream_size, bytes_per_cycle, std.fmt.fmtSliceHexLower(stream[0..64]) });

}

fn cyclesPerByte(nanoseconds: i128, bytes: usize) f64 {
    const ns_f64 = @intToFloat(f64, nanoseconds);
    const clocks = ns_f64 * cycles_per_nanosecond;
    const b_f64 = @intToFloat(f64, bytes);
    return b_f64 / clocks;
}
