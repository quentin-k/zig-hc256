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

    const cpb_1 = cyclesPerByte(elapsed, 64 * 2 * iterations);
    try stdout.print(
        \\It took {d:>.4}s for repeated encryption
        \\clock cycles: {d:>.3}
        \\cycles per byte: {d:>.4}
        \\message: {}
        \\
    , .{
        @intToFloat(f64, elapsed) / @intToFloat(f64, std.time.ns_per_s),
        @intToFloat(f64, elapsed) * cycles_per_nanosecond,
        cpb_1,
        std.fmt.fmtSliceHexLower(&msg),
    });

    const stream_size = iterations * 2 * 64;
    var stream: []u8 = try allocator.alloc(u8, stream_size);
    defer allocator.free(stream);

    timer.reset();
    _ = cipher.applyStreamFast(stream);
    elapsed = timer.read();
    const cpb_2 = cyclesPerByte(elapsed, stream_size);

    try stdout.print(
        \\It took {d:>.4}s to encrypted {} bytes of data
        \\clock cycles: {d:>.3}
        \\cycles per byte: {d:>.4}
        \\message[0..64]: {}
        \\
    , .{
        @intToFloat(f64, elapsed) / @intToFloat(f64, std.time.ns_per_s),
        stream_size,
        @intToFloat(f64, elapsed) * cycles_per_nanosecond,
        cpb_2,
        std.fmt.fmtSliceHexLower(stream[0..64]),
    });
}

fn cyclesPerByte(nanoseconds: u64, bytes: usize) f64 {
    const clockcycles = @intToFloat(f64, nanoseconds) * cycles_per_nanosecond;
    const b_f64 = @intToFloat(f64, bytes);
    return clockcycles / b_f64;
}
